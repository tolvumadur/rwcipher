//Read and write asynchronously to encrypted files.
package rwcipher

import(
    "errors"
    "fmt"
    "golang.org/x/crypto/ssh/terminal"
)

// Usually read from STDIN (0) but can be changed for testing
var terminalFD int = 0

func Hello(name string) string {
    message := fmt.Sprintf("Hi %v, Welcome to the RWCIPHER read/writer.\nBeware of race conditions", name)
    return message
}

// Async read an encrypted file
func ReadEncRaw(path string, killswitch chan bool ) chan byte {
    reader := make(chan byte, 64000000) // 64 MB buffer
    return reader
}

// Async read an encrypted CSV
func ReadEncCSV(path string, killswitch chan bool) (chan *[]string, error) {
    return make(chan *[]string, 1000), errors.New("Not Implemented")
}

//Async read encrypted JSON file
func ReadEncJSON(path string, killswitch chan bool) (chan *map[string]interface{}, error){
    return make(chan *map[string]interface{}, 100), errors.New("Not Implemented")
}

// Write raw data to encrypted file
func WriteEncRaw(bytes chan byte) error {
    return errors.New("Not Yet Implemented")
}

// Write a list of rows to CSV
func WriteEncCSV(rows chan *[]string) error {
    return errors.New("Not Yet Implemented")
}

// Write unstructured JSON to encrypted file
func WriteEncJSON(j chan []map[string]interface{}) error {
    return errors.New("Not Yet Implemented")
}

//Get password bytes from user
func getPassword(filename string) (pwd []byte, err error) {
    fmt.Println("Enter password for " + filename)
    if pwd, err = terminal.ReadPassword(terminalFD); err != nil {
        return
    } 

    //TODO: Add some sanity checks or warnings for weak passwords?
    return    
}