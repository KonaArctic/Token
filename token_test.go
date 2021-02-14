// Very basic test
package token
import "testing"

func TestMain ( test * testing.T ) {
	var err error
	var token Token
	var config Config
	token.Ident = 100
	token.Expire = 100
	token.Payload = string( "Hello, World!" )
	test.Logf( "token: %v" , token.Binary( ) )

	token , err = Parse( token.String( ) )
	if err != nil {
		test.Fatalf( "%s\r\n" , err.Error( ) ) }
	if token.Ident != 100 {
		test.Fatalf( "ident mismatch: %d\r\n" , token.Ident ) }
	if token.Payload != "Hello, World!" {
		test.Fatalf( "payload mismatch: %d\r\n" , token.Payload ) }

	token.Expire = -1
	token , err = Cast( token.Binary( ) )
	if err == nil || err.Error( ) != "TOKEN: Expired" {
		test.Fatalf( "token expired: %d\r\n" , token.Expire ) }

	token.Expire = 10
	token.Service = 12
	config.Service = 32
	config.Secret = Secret
	test.Logf( "token: %v" , token.Binary( ) )
	token , err = config.Cast( token.Binary( ) )
	if err == nil || err.Error( ) != "TOKEN: Unauthorized" {
		test.Fatalf( "token unauthorized: %d\r\n" , token.Expire ) }

	return
}


