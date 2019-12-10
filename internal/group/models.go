package group

// Chat represents a group chat.
type Chat struct {
	ID      string   `bson:"_id,omitempty"`
	Name    string   `bson:"name"`
	Admin   string   `bson:"admin"`
	Members []string `bson:"members"`
}

// NewChat contains information needed to create a new group chat.
type NewChat struct {
	Name    string
	Admin   string
	Members []string
}
