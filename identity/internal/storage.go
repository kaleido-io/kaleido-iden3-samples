// Copyright © 2022 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
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

package internal

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	sqlstorage "github.com/iden3/go-merkletree-sql/db/sql"
	_ "github.com/mattn/go-sqlite3"
)

const SqlStorageSchema = `CREATE TABLE IF NOT EXISTS mt_nodes (
	mt_id BIGINT,
	key BYTEA,
	type SMALLINT NOT NULL,
	child_l BYTEA,
	child_r BYTEA,
	entry BYTEA,
	created_at BIGINT,
	deleted_at BIGINT,
	PRIMARY KEY(mt_id, key)
);

CREATE TABLE IF NOT EXISTS mt_roots (
	mt_id BIGINT PRIMARY KEY,
	key BYTEA,
	created_at BIGINT,
	deleted_at BIGINT
);`

func initMerkleTreeDB(name string) (*sql.DB, error) {
	homedir, _ := os.UserHomeDir()
	dbPath := filepath.Join(homedir, fmt.Sprintf("iden3/%s.db", name))
	_ = os.MkdirAll(filepath.Dir(dbPath), os.ModePerm)
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("Failed to open sqlite db: %s\n", err)
		os.Exit(1)
	}

	if _, err := db.Exec(SqlStorageSchema); err != nil {
		return nil, err
	}
	return db, nil
}

type sqlDB struct {
	db *sql.DB
}

func (s *sqlDB) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return s.db.ExecContext(ctx, query, args...)
}

func (s *sqlDB) GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	result, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer result.Close()
	if result.Next() {
		switch item := dest.(type) {
		case *sqlstorage.RootItem:
			return result.Scan(&item.MTId, &item.Key, &item.DeletedAt, &item.CreatedAt)
		case *sqlstorage.NodeItem:
			return result.Scan(&item.MTId, &item.Key, &item.Type, &item.ChildL, &item.ChildR, &item.Entry, &item.CreatedAt, &item.DeletedAt)
		}
	}
	return sql.ErrNoRows
}

func (s *sqlDB) SelectContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	return fmt.Errorf("not implemented")
}
