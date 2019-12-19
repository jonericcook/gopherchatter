package chat

import "go.mongodb.org/mongo-driver/bson/primitive"

const (
	// GroupLabel is the name of the chat type.
	GroupLabel = "group"
	// GroupMemberLimit is limit of members in a group chat.
	GroupMemberLimit = 1000
	// IndividualLabel is the label of the chat type.
	IndividualLabel = "individual"
	// IndividualMemberLimit is limit of members in a individual chat.
	IndividualMemberLimit = 2
)

// Group represents a group chat.
type Group struct {
	ID      primitive.ObjectID   `bson:"_id,omitempty"`
	Name    string               `bson:"name"`
	Type    string               `bson:"type"`
	Admins  []primitive.ObjectID `bson:"admins"`
	Members []primitive.ObjectID `bson:"members"`
}

// Individual represents an individual chat.
type Individual struct {
	ID      primitive.ObjectID   `bson:"_id,omitempty"`
	Type    string               `bson:"type"`
	Members []primitive.ObjectID `bson:"members"`
}
