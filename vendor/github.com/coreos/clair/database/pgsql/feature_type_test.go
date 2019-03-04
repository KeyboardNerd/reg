package pgsql

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
)

func TestGetFeatureTypeMap(t *testing.T) {
	tx, cleanup := createTestPgSession(t, "TestGetFeatureTypeMap")
	defer cleanup()

	types, err := tx.getFeatureTypeMap()
	if err != nil {
		require.Nil(t, err, err.Error())
	}

	require.Equal(t, database.SourcePackage, types.byID[1])
	require.Equal(t, database.BinaryPackage, types.byID[2])
	require.Equal(t, 1, types.byName[database.SourcePackage])
	require.Equal(t, 2, types.byName[database.BinaryPackage])
}
