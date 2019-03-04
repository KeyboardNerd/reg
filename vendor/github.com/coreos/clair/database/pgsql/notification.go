// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pgsql

import (
	"database/sql"
	"errors"
	"time"

	"github.com/guregu/null/zero"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/pagination"
)

const (
	insertNotification = `
		INSERT INTO Vulnerability_Notification(name, created_at, old_vulnerability_id, new_vulnerability_id)
		VALUES ($1, $2, $3, $4)`

	updatedNotificationAsRead = `
		UPDATE Vulnerability_Notification
		SET notified_at = CURRENT_TIMESTAMP
		WHERE name = $1`

	removeNotification = `
		UPDATE Vulnerability_Notification
	  SET deleted_at = CURRENT_TIMESTAMP
	  WHERE name = $1 AND deleted_at IS NULL`

	searchNotificationAvailable = `
		SELECT name, created_at, notified_at, deleted_at
		FROM Vulnerability_Notification
		WHERE (notified_at IS NULL OR notified_at < $1)
					AND deleted_at IS NULL
					AND name NOT IN (SELECT name FROM Lock)
		ORDER BY Random()
		LIMIT 1`

	searchNotification = `
		SELECT created_at, notified_at, deleted_at, old_vulnerability_id, new_vulnerability_id
		FROM Vulnerability_Notification
		WHERE name = $1`

	searchNotificationVulnerableAncestry = `
	   SELECT DISTINCT ON (a.id)
			a.id, a.name
		FROM vulnerability_affected_namespaced_feature AS vanf,
			ancestry_layer AS al, ancestry_feature AS af, ancestry AS a
		WHERE vanf.vulnerability_id = $1
			AND a.id >= $2
			AND al.ancestry_id = a.id
			AND al.id = af.ancestry_layer_id
			AND af.namespaced_feature_id = vanf.namespaced_feature_id
		ORDER BY a.id ASC
		LIMIT $3;`
)

var (
	errNotificationNotFound = errors.New("requested notification is not found")
)

func (tx *pgSession) InsertVulnerabilityNotifications(notifications []database.VulnerabilityNotification) error {
	if len(notifications) == 0 {
		return nil
	}

	var (
		newVulnIDMap = make(map[database.VulnerabilityID]sql.NullInt64)
		oldVulnIDMap = make(map[database.VulnerabilityID]sql.NullInt64)
	)

	invalidCreationTime := time.Time{}
	for _, noti := range notifications {
		if noti.Name == "" {
			return commonerr.NewBadRequestError("notification should not have empty name")
		}
		if noti.Created == invalidCreationTime {
			return commonerr.NewBadRequestError("notification should not have empty created time")
		}

		if noti.New != nil {
			key := database.VulnerabilityID{
				Name:      noti.New.Name,
				Namespace: noti.New.Namespace.Name,
			}
			newVulnIDMap[key] = sql.NullInt64{}
		}

		if noti.Old != nil {
			key := database.VulnerabilityID{
				Name:      noti.Old.Name,
				Namespace: noti.Old.Namespace.Name,
			}
			oldVulnIDMap[key] = sql.NullInt64{}
		}
	}

	var (
		newVulnIDs = make([]database.VulnerabilityID, 0, len(newVulnIDMap))
		oldVulnIDs = make([]database.VulnerabilityID, 0, len(oldVulnIDMap))
	)

	for vulnID := range newVulnIDMap {
		newVulnIDs = append(newVulnIDs, vulnID)
	}

	for vulnID := range oldVulnIDMap {
		oldVulnIDs = append(oldVulnIDs, vulnID)
	}

	ids, err := tx.findNotDeletedVulnerabilityIDs(newVulnIDs)
	if err != nil {
		return err
	}

	for i, id := range ids {
		if !id.Valid {
			return handleError("findNotDeletedVulnerabilityIDs", errVulnerabilityNotFound)
		}
		newVulnIDMap[newVulnIDs[i]] = id
	}

	ids, err = tx.findLatestDeletedVulnerabilityIDs(oldVulnIDs)
	if err != nil {
		return err
	}

	for i, id := range ids {
		if !id.Valid {
			return handleError("findLatestDeletedVulnerabilityIDs", errVulnerabilityNotFound)
		}
		oldVulnIDMap[oldVulnIDs[i]] = id
	}

	var (
		newVulnID sql.NullInt64
		oldVulnID sql.NullInt64
	)

	keys := make([]interface{}, len(notifications)*4)
	for i, noti := range notifications {
		if noti.New != nil {
			newVulnID = newVulnIDMap[database.VulnerabilityID{
				Name:      noti.New.Name,
				Namespace: noti.New.Namespace.Name,
			}]
		}

		if noti.Old != nil {
			oldVulnID = oldVulnIDMap[database.VulnerabilityID{
				Name:      noti.Old.Name,
				Namespace: noti.Old.Namespace.Name,
			}]
		}

		keys[4*i] = noti.Name
		keys[4*i+1] = noti.Created
		keys[4*i+2] = oldVulnID
		keys[4*i+3] = newVulnID
	}

	// NOTE(Sida): The data is not sorted before inserting into database under
	// the fact that there's only one updater running at a time. If there are
	// multiple updaters, deadlock may happen.
	_, err = tx.Exec(queryInsertNotifications(len(notifications)), keys...)
	if err != nil {
		return handleError("queryInsertNotifications", err)
	}

	return nil
}

func (tx *pgSession) FindNewNotification(notifiedBefore time.Time) (database.NotificationHook, bool, error) {
	var (
		notification database.NotificationHook
		created      zero.Time
		notified     zero.Time
		deleted      zero.Time
	)

	err := tx.QueryRow(searchNotificationAvailable, notifiedBefore).Scan(&notification.Name, &created, &notified, &deleted)
	if err != nil {
		if err == sql.ErrNoRows {
			return notification, false, nil
		}
		return notification, false, handleError("searchNotificationAvailable", err)
	}

	notification.Created = created.Time
	notification.Notified = notified.Time
	notification.Deleted = deleted.Time

	return notification, true, nil
}

func (tx *pgSession) findPagedVulnerableAncestries(vulnID int64, limit int, currentToken pagination.Token) (database.PagedVulnerableAncestries, error) {
	vulnPage := database.PagedVulnerableAncestries{Limit: limit}
	currentPage := Page{0}
	if currentToken != pagination.FirstPageToken {
		if err := tx.key.UnmarshalToken(currentToken, &currentPage); err != nil {
			return vulnPage, err
		}
	}

	if err := tx.QueryRow(searchVulnerabilityByID, vulnID).Scan(
		&vulnPage.Name,
		&vulnPage.Description,
		&vulnPage.Link,
		&vulnPage.Severity,
		&vulnPage.Metadata,
		&vulnPage.Namespace.Name,
		&vulnPage.Namespace.VersionFormat,
	); err != nil {
		return vulnPage, handleError("searchVulnerabilityByID", err)
	}

	// the last result is used for the next page's startID
	rows, err := tx.Query(searchNotificationVulnerableAncestry, vulnID, currentPage.StartID, limit+1)
	if err != nil {
		return vulnPage, handleError("searchNotificationVulnerableAncestry", err)
	}
	defer rows.Close()

	ancestries := []affectedAncestry{}
	for rows.Next() {
		var ancestry affectedAncestry
		err := rows.Scan(&ancestry.id, &ancestry.name)
		if err != nil {
			return vulnPage, handleError("searchNotificationVulnerableAncestry", err)
		}
		ancestries = append(ancestries, ancestry)
	}

	lastIndex := 0
	if len(ancestries)-1 < limit {
		lastIndex = len(ancestries)
		vulnPage.End = true
	} else {
		// Use the last ancestry's ID as the next page.
		lastIndex = len(ancestries) - 1
		vulnPage.Next, err = tx.key.MarshalToken(Page{ancestries[len(ancestries)-1].id})
		if err != nil {
			return vulnPage, err
		}
	}

	vulnPage.Affected = map[int]string{}
	for _, ancestry := range ancestries[0:lastIndex] {
		vulnPage.Affected[int(ancestry.id)] = ancestry.name
	}

	vulnPage.Current, err = tx.key.MarshalToken(currentPage)
	if err != nil {
		return vulnPage, err
	}

	return vulnPage, nil
}

func (tx *pgSession) FindVulnerabilityNotification(name string, limit int, oldPageToken pagination.Token, newPageToken pagination.Token) (
	database.VulnerabilityNotificationWithVulnerable, bool, error) {
	var (
		noti      database.VulnerabilityNotificationWithVulnerable
		oldVulnID sql.NullInt64
		newVulnID sql.NullInt64
		created   zero.Time
		notified  zero.Time
		deleted   zero.Time
	)

	if name == "" {
		return noti, false, commonerr.NewBadRequestError("Empty notification name is not allowed")
	}

	noti.Name = name
	err := tx.QueryRow(searchNotification, name).Scan(&created, &notified,
		&deleted, &oldVulnID, &newVulnID)

	if err != nil {
		if err == sql.ErrNoRows {
			return noti, false, nil
		}
		return noti, false, handleError("searchNotification", err)
	}

	if created.Valid {
		noti.Created = created.Time
	}

	if notified.Valid {
		noti.Notified = notified.Time
	}

	if deleted.Valid {
		noti.Deleted = deleted.Time
	}

	if oldVulnID.Valid {
		page, err := tx.findPagedVulnerableAncestries(oldVulnID.Int64, limit, oldPageToken)
		if err != nil {
			return noti, false, err
		}
		noti.Old = &page
	}

	if newVulnID.Valid {
		page, err := tx.findPagedVulnerableAncestries(newVulnID.Int64, limit, newPageToken)
		if err != nil {
			return noti, false, err
		}
		noti.New = &page
	}

	return noti, true, nil
}

func (tx *pgSession) MarkNotificationAsRead(name string) error {
	if name == "" {
		return commonerr.NewBadRequestError("Empty notification name is not allowed")
	}

	r, err := tx.Exec(updatedNotificationAsRead, name)
	if err != nil {
		return handleError("updatedNotificationAsRead", err)
	}

	affected, err := r.RowsAffected()
	if err != nil {
		return handleError("updatedNotificationAsRead", err)
	}

	if affected <= 0 {
		return handleError("updatedNotificationAsRead", errNotificationNotFound)
	}
	return nil
}

func (tx *pgSession) DeleteNotification(name string) error {
	if name == "" {
		return commonerr.NewBadRequestError("Empty notification name is not allowed")
	}

	result, err := tx.Exec(removeNotification, name)
	if err != nil {
		return handleError("removeNotification", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return handleError("removeNotification", err)
	}

	if affected <= 0 {
		return handleError("removeNotification", commonerr.ErrNotFound)
	}

	return nil
}
