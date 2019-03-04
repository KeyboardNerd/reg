package pgsql

import "github.com/coreos/clair/database"

const (
	selectAllFeatureTypes = `SELECT id, name FROM feature_type`
)

type featureTypes struct {
	byID   map[int]database.FeatureType
	byName map[database.FeatureType]int
}

func newFeatureTypes() *featureTypes {
	return &featureTypes{make(map[int]database.FeatureType), make(map[database.FeatureType]int)}
}

func (tx *pgSession) getFeatureTypeMap() (*featureTypes, error) {
	rows, err := tx.Query(selectAllFeatureTypes)
	if err != nil {
		return nil, err
	}

	types := newFeatureTypes()
	for rows.Next() {
		var (
			id   int
			name database.FeatureType
		)
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}

		types.byID[id] = name
		types.byName[name] = id
	}

	return types, nil
}
