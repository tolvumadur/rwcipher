package rwcipher

import(
    //"os"
    "errors"
    //"encoding/json"
    //"encoding/csv"
    "syscall"
    "fmt"

    "golang.org/x/crypto/ssh/terminal"
)

// OpenEncRaw will read an encrypted
func ReadEncRaw(path string, killswitch chan bool ) chan byte {
    reader := make(chan byte, 64000000) // 64 MB buffer
    return reader
}

func ReadEncCSV(path string, killswitch chan bool) (chan *[]string, error) {
    return make(chan *[]string, 1000), errors.New("Not Implemented")
}

//ReadEnc
func ReadEncJSON(path string, killswitch chan bool) (chan *map[string]interface{}, error){
    return make(chan *map[string]interface{}, 100), errors.New("Not Implemented")
}

func WriteEncRaw(bytes []byte) error {
    return errors.New("Not Yet Implemented")
}

func WriteEncCSV(*[]string, error) error {
    return errors.New("Not Yet Implemented")
}

func WriteEncJSON(j []map[string]interface{}) error {
    return errors.New("Not Yet Implemented")
}

//Get password bytes from user
func getPassword(filename string) (pwd []byte, err error) {
    fmt.Println("Enter password for " + filename)
    if pwd, err = terminal.ReadPassword(int(syscall.Stdin)); err != nil {
        return
    } 

    //TODO: Add some sanity checks or warnings for weak passwords?
    return    
}