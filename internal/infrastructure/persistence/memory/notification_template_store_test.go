package memory

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/testutil/notificationtemplatetest"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestNotificationTemplateStoreConformance(t *testing.T) {
	notificationtemplatetest.Run(t, func(*testing.T) ports.NotificationTemplateStore {
		return NewNotificationTemplateStore()
	})
}
