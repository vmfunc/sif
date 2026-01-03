/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package modules

import "sync"

var (
	registry = make(map[string]Module)
	mu       sync.RWMutex
)

// Register adds a module to the registry.
// If a module with the same ID already exists, it will be overwritten.
func Register(m Module) {
	mu.Lock()
	defer mu.Unlock()
	registry[m.Info().ID] = m
}

// Get returns a module by ID.
// The second return value indicates whether the module was found.
func Get(id string) (Module, bool) {
	mu.RLock()
	defer mu.RUnlock()
	m, ok := registry[id]
	return m, ok
}

// All returns all registered modules.
func All() []Module {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Module, 0, len(registry))
	for _, m := range registry {
		result = append(result, m)
	}
	return result
}

// ByTag returns modules matching a tag.
func ByTag(tag string) []Module {
	mu.RLock()
	defer mu.RUnlock()
	var result []Module
	for _, m := range registry {
		for _, t := range m.Info().Tags {
			if t == tag {
				result = append(result, m)
				break
			}
		}
	}
	return result
}

// ByType returns modules of a specific type.
func ByType(t ModuleType) []Module {
	mu.RLock()
	defer mu.RUnlock()
	var result []Module
	for _, m := range registry {
		if m.Type() == t {
			result = append(result, m)
		}
	}
	return result
}

// Count returns the number of registered modules.
func Count() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(registry)
}

// Clear removes all modules from the registry.
// This is primarily useful for testing.
func Clear() {
	mu.Lock()
	defer mu.Unlock()
	registry = make(map[string]Module)
}
