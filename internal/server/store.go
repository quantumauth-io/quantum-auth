package server

import "sync"

type Store struct {
	mu         sync.RWMutex
	users      map[string]*User
	devices    map[string]*Device
	challenges map[string]*Challenge
}

func NewStore() *Store {
	return &Store{
		users:      make(map[string]*User),
		devices:    make(map[string]*Device),
		challenges: make(map[string]*Challenge),
	}
}

func (s *Store) AddUser(u *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.ID] = u
}

func (s *Store) GetUserByID(id string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[id]
}

func (s *Store) GetUserByEmail(email string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Email == email {
			return u
		}
	}
	return nil
}

// --- devices ---

func (s *Store) AddDevice(d *Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[d.ID] = d
}

func (s *Store) GetDevice(id string) *Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.devices[id]
}

// --- challenges ---

func (s *Store) AddChallenge(c *Challenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[c.ID] = c
}

func (s *Store) GetChallenge(id string) *Challenge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.challenges[id]
}

func (s *Store) DeleteChallenge(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.challenges, id)
}
