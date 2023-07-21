package kvstore

import (
	"encoding/json"
	"github.com/kaleido-io/kaleido-iden3-verifier/internal/messages"
	"github.com/syndtr/goleveldb/leveldb"
)

type AuthRequestMessage = messages.AuthorizationRequestMessageWithStatus

type KVStore interface {
  Put(key string, val AuthRequestMessage) error
  Get(key string) (AuthRequestMessage, error)
}

type levelDBKeyValueStore struct {
  path string
  db *leveldb.DB
}

func NewKVStore(path string) (kv KVStore, err error) {
  db, err := leveldb.OpenFile(path, nil)

  if err != nil {
    return nil, err
  }

  kv = &levelDBKeyValueStore{
    path,
    db,
  }
  return
}

func (k *levelDBKeyValueStore) Put(key string, val AuthRequestMessage) error {
  b, err := json.Marshal(val)
  if err != nil {
    return err
  }

  err = k.db.Put([]byte(key), b, nil)
  return err
}

func (k *levelDBKeyValueStore) Get(key string) (AuthRequestMessage, error) {
  b, err := k.db.Get([]byte(key), nil)
  msg := AuthRequestMessage{}
  err = json.Unmarshal(b, &msg)
  return msg, err
}
