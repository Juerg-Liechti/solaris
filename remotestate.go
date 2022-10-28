package main

type RemoteState struct {
	InFile  string `json:"in_file"`
	Name    string `json:"name"`
	Bucket  string `json:"storage_account_name"`
	Key     string `json:"key"`
	Profile string `json:"resource_group_name"`
	Region  string `json:"container_name"`
}

func (orig RemoteState) equals(other RemoteState) bool {
	if orig.Bucket == other.Bucket &&
		orig.Key == other.Key &&
		orig.Profile == other.Profile &&
		orig.Region == other.Region {
		return true
	}
	return false
}
