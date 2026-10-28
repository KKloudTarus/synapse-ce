package documentproviders

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func Register(registry *integration.Registry) error {
	if registry == nil {
		return shared.ErrValidation
	}
	for _, item := range []struct {
		descriptor integration.ProviderDescriptor
		factory    integration.Factory
	}{{graphDescriptor(SharePoint), newGraph}, {graphDescriptor(OneDrive), newGraph}, {driveDescriptor, newDrive}, {notionDescriptor, newNotion}, {s3Descriptor, newS3}} {
		if err := registry.Register(item.descriptor, item.factory); err != nil {
			return err
		}
	}
	return nil
}
