package checks

import (
	"github.com/argus-security/argus/internal/model"
)

var registry []model.CheckItem

func Register(items ...model.CheckItem) {
	for _, item := range items {
		if !item.MatchesPlatform() {
			continue
		}
		registry = append(registry, item)
	}
}

func GetAll() []model.CheckItem {
	return registry
}
