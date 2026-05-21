package kernel

import (
	"fmt"
	"reflect"
	"sync"
)

type Container struct {
	mu       sync.RWMutex
	bindings map[reflect.Type]interface{}
	aliases  map[string]reflect.Type
}

func NewContainer() *Container {
	return &Container{
		bindings: make(map[reflect.Type]interface{}),
		aliases:  make(map[string]reflect.Type),
	}
}

func (c *Container) Bind(iface interface{}, impl interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := reflect.TypeOf(iface)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	c.bindings[t] = impl
}

func (c *Container) BindNamed(name string, iface interface{}, impl interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := reflect.TypeOf(iface)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	c.bindings[t] = impl
	c.aliases[name] = t
}

func (c *Container) Resolve(iface interface{}) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	t := reflect.TypeOf(iface)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() == reflect.Interface {
		impl, ok := c.bindings[t]
		return impl, ok
	}
	for key, val := range c.bindings {
		if key == t {
			return val, true
		}
	}
	return nil, false
}

func (c *Container) ResolveNamed(name string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	t, ok := c.aliases[name]
	if !ok {
		return nil, false
	}
	impl, ok := c.bindings[t]
	return impl, ok
}

func (c *Container) Inject(target interface{}) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	targetVal := reflect.ValueOf(target)
	if targetVal.Kind() != reflect.Ptr || targetVal.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("Inject: target must be a pointer to struct, got %v", targetVal.Kind())
	}

	elem := targetVal.Elem()
	elemType := elem.Type()

	for i := 0; i < elemType.NumField(); i++ {
		field := elemType.Field(i)
		tag := field.Tag.Get("inject")
		if tag == "" {
			continue
		}

		fieldVal := elem.Field(i)
		if !fieldVal.CanSet() {
			continue
		}

		var impl interface{}
		var ok bool

		if tag != "" && tag != "true" {
			resolvedType, aliasOk := c.aliases[tag]
			if aliasOk {
				impl, ok = c.bindings[resolvedType]
			}
		}

		if !ok {
			fieldType := field.Type
			if fieldType.Kind() == reflect.Interface {
				for _, binding := range c.bindings {
					if reflect.TypeOf(binding).Implements(fieldType) {
						impl = binding
						ok = true
						break
					}
				}
			}
		}

		if !ok {
			fieldType := field.Type
			for _, binding := range c.bindings {
				if reflect.TypeOf(binding).AssignableTo(fieldType) {
					impl = binding
					ok = true
					break
				}
			}
		}

		if ok {
			fieldVal.Set(reflect.ValueOf(impl))
		}
	}

	return nil
}

func (c *Container) Remove(iface interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := reflect.TypeOf(iface)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	delete(c.bindings, t)
}

func (c *Container) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.bindings)
}