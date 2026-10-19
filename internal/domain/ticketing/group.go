package ticketing

import "errors"

// ErrGroupBusy means another durable command owns this group. A new member has
// not been admitted and must retry with a fresh preview after that command ends.
var ErrGroupBusy = errors.New("ticket group has an active command")
