package token
import "crypto/sha256"
import "encoding/base64"
import "encoding/binary"
import "encoding/json"
import "errors"
import "os"
import "time"


//
// Da object
type Token struct{
	Secret [ ]byte;
	Service uint16;
	Ident uint64;
	ladder uint32;	// Not in use yet
	Expire int64;
	Payload interface{ };
	sha224 [ sha256.Size224 ]byte;	// ?
}


//
// Defaults
var Secret = [ ]byte( ternary( os.Getenv( "AKONA_TOKEN_SECRET" ) != "" , os.Getenv( "AKONA_TOKEN_SECRET" ) ,
	"q7MPygpivEqyG9gC9ue69QeCOvTrScBZ" ).( string ) )
var Service uint16 = 0
var Control string = "wss://account.akona.me/control"
var Expire int64 = 240


//
// Configs
type Config struct{ 
	Secret [ ]byte;
	Service uint16;
	Control string;
}

func Parse( input string ) ( Token , error ) {
	return ( & Config{ Secret , Service , Control } ).Parse( input )
}

func Cast( input [ ]byte ) ( Token , error ) {
	return ( & Config{ Secret , Service , Control } ).Cast( input )
}


//
// Parse from string
func ( self Config )Parse( input string ) ( Token , error ) {
	var err error
	var binary [ ]byte

	binary , err = base64.RawURLEncoding.DecodeString( input )
	if err != nil {
		return * new( Token ) , err }

	return Cast( binary )
}


//
// Or binary
func ( self Config )Cast( input [ ]byte ) ( Token , error ) {
	var token Token
	var index int

	if self.Secret == nil {
		self.Secret = Secret }
	if len( self.Secret ) < sha256.Size224 {
		panic( "refusing to validate unsecret tokens" ) }
	if self.Service == 0 {
		self.Service = Service }

	if len( input ) < binary.MaxVarintLen16 + binary.MaxVarintLen64 + binary.MaxVarintLen32 + binary.MaxVarintLen64 + sha256.Size224 {
		return token , errors.New( "TOKEN: Invalid" ) }

	token.Service = uint16( mu( binary.Uvarint( input[ 0 : binary.MaxVarintLen16 ] ) )[ 0 ].( uint64 ) )
	index = binary.MaxVarintLen16
	token.Ident = mu( binary.Uvarint( input[ index : index + binary.MaxVarintLen64 ] ) )[ 0 ].( uint64 )
	index += binary.MaxVarintLen64
	token.ladder = uint32( mu( binary.Uvarint( input[ index : index + binary.MaxVarintLen32 ] ) )[ 0 ].( uint64 ) )
	index += binary.MaxVarintLen32
	token.Expire = mu( binary.Varint( input[ index : index + binary.MaxVarintLen64 ] ) )[ 0 ].( int64 ) - time.Now( ).Unix( )
	index += binary.MaxVarintLen64

	err := json.Unmarshal( input[ index + sha256.Size224 : ] , & token.Payload )
	if err != nil {
		return token , err }

	copy( token.sha224[ : sha256.Size224 ] , input[ index : ] )
	copy( input[ index : index + sha256.Size224 ] , self.Secret )
	if token.sha224 != sha256.Sum224( input ) {	// Hello timing attacks
		return token , errors.New( "TOKEN: Invalid" ) }
	index += sha256.Size224

	if token.Expire <= 0 {
		return token , errors.New( "TOKEN: Expired" ) }
	if self.Service > 0 && token.Service != self.Service {
		return token , errors.New( "TOKEN: Unauthorized" ) }

	return token , nil
}


//
// Convert to bytes
func ( self Token ) Binary( ) [ ]byte {
	var bytes = make( [ ]byte , binary.MaxVarintLen16 + binary.MaxVarintLen64 + binary.MaxVarintLen32 + binary.MaxVarintLen64 + len( mu( json.Marshal( self.Payload ) )[ 0 ].( [ ]byte ) ) + sha256.Size224 )
	var index int

	if self.Secret == nil {
		self.Secret = Secret }
	if len( self.Secret ) < sha256.Size224 {
		panic( "refusing to generate unsecret tokens" ) }
	if self.Service == 0 {
		self.Service = Service }
	if self.Expire == 0 {
		self.Expire = Expire }

	binary.PutUvarint( bytes[ 0 : ] , uint64( self.Service ) )
	index = binary.MaxVarintLen16
	binary.PutUvarint( bytes[ index : ] , self.Ident )
	index += binary.MaxVarintLen64
	binary.PutUvarint( bytes[ index : ] , uint64 ( self.ladder ) )
	index += binary.MaxVarintLen32
	binary.PutVarint( bytes[ index : ] , self.Expire + time.Now( ).Unix( ) )
	index += binary.MaxVarintLen64

	json , _ := json.Marshal( self.Payload )
	index += sha256.Size224
	copy( bytes[ index : ] , [ ]byte( string( json ) + "\n" ) )
	index -= sha256.Size224

	copy( bytes[ index : index + sha256.Size224 ] , self.Secret )
	self.sha224 = sha256.Sum224( bytes )	// Why does Sum224 return a byte array?
	copy( bytes[ index : ] , self.sha224[ : ] )

	return bytes
}


//
// Or string
func ( self Token ) String( ) string {
	return base64.RawURLEncoding.EncodeToString( self.Binary( ) )
}


