package storage

type DbClipboard struct {
	ID         int    `json:"id" storm:"id,increment"`
	Uid        int    `json:"uid" storm:"index"`
	Content    string `json:"content"`
	CreateTime int64  `json:"create_time" storm:"index"`
}

func ClipboardCreate(o *DbClipboard) (*DbClipboard, error) {
	err := db.Save(o)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func ClipboardList() ([]DbClipboard, error) {
	var os []DbClipboard
	err := db.All(&os)
	if err != nil {
		return nil, err
	}
	return os, nil
}

func ClipboardGet(id int) (*DbClipboard, error) {
	var o DbClipboard
	err := db.One("ID", id, &o)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func ClipboardDelete(id int) error {
	o := &DbClipboard{
		ID: id,
	}
	err := db.DeleteStruct(o)
	if err != nil {
		return err
	}
	return nil
}
