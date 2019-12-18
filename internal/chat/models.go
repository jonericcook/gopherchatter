package chat

import "go.mongodb.org/mongo-driver/bson/primitive"

// Type is the type of chat.
var Type = struct {
	Group struct {
		Name        string
		MemberLimit int
		HasAdmins   bool
	}
	Individual struct {
		Name        string
		MemberLimit int
		HasAdmins   bool
	}
}{
	Group: struct {
		Name        string
		MemberLimit int
		HasAdmins   bool
	}{
		Name:        "group",
		MemberLimit: 999,
		HasAdmins:   true,
	},
	Individual: struct {
		Name        string
		MemberLimit int
		HasAdmins   bool
	}{
		Name:        "individual",
		MemberLimit: 2,
		HasAdmins:   false,
	},
}

var v = Type.Group.Name

// Chat represents a chat.
type Chat struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty"`
	Name        string               `bson:"name,omitempty"`
	Type        string               `bson:"type"`
	Admins      []primitive.ObjectID `bson:"admins,omitempty"`
	Members     []primitive.ObjectID `bson:"members"`
	MemberLimit int                  `bson:"member_limit"`
}
