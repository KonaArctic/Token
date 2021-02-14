package token
import "crypto/sha256"
import "encoding/base64"
import "encoding/binary"
import "encoding/json"
import "errors"
import "time"

// Da object
type Token struct{
	Service uint16;
	Ident uint64;
	ladder uint32;	// Not in use yet
	Expire int64;
	Payload interface{ };
	sha224 [ sha256.Size224 ]byte;
}

// Defaults
var Secret = [ ]byte{ 0xd7, 0xda, 0x66, 0xf7, 0x9b, 0x34, 0xea, 0xea, 0xd7, 0xc1, 0x08, 0xd5, 0x54, 0x0e, 0x13, 0x3c, 0xc7, 0x54, 0x6e, 0x30, 0x82, 0xdc, 0x7c, 0x58, 0xbc, 0xdf, 0xb4, 0xac, 0x7e, 0x6c, 0x65, 0xf2, 0x81, 0x91, 0x5f, 0x7e, 0x72, 0x88, 0x31, 0x55, 0x7c, 0xd8, 0x30, 0x5b, 0x57, 0x2c, 0xa7, 0x24, 0xd5, 0xd3, 0xc6, 0xfe, 0xeb, 0x0f, 0x23, 0x9a, 0x6d, 0x9c, 0x39, 0xcd, 0xcf, 0xeb, 0xf5, 0x8e }
const Control string = "wss://account.akona.me/control"
const Service uint16 = 0

// https://stackoverflow.com/a/50346080/10958912 
func mu( a ... interface{ } ) [ ]interface{ } {
    return a
}

// Parse from string
func Parse( input string ) ( Token , error ) {
	var err error
	var binary [ ]byte
	
	binary , err = base64.RawStdEncoding.DecodeString( input )
	if err != nil {
		return * new( Token ) , err }

	return Cast( binary )
}

// Or binary
func Cast( input [ ]byte ) ( Token , error ) {
	var token Token
	var index int

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
	copy( input[ index : ] , Secret[ : sha256.Size224 ] )
	if token.sha224 != sha256.Sum224( input ) {	// Hello timing attacks
		return token , errors.New( "TOKEN: Invalid" ) }
	index += sha256.Size224

	if token.Expire <= 0 {
		return token , errors.New( "TOKEN: Expired" ) }

	return token , nil
}

// Convert to bytes
func ( self * Token ) Binary( ) [ ]byte {
	var bytes = make( [ ]byte , binary.MaxVarintLen16 + binary.MaxVarintLen64 + binary.MaxVarintLen32 + binary.MaxVarintLen64 + len( mu( json.Marshal( self.Payload ) )[ 0 ].( [ ]byte ) ) + sha256.Size224 )
	var index int

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
	copy( bytes[ index : ] , [ ]byte( json ) )
	index -= sha256.Size224

	copy( bytes[ index : ] , Secret[ : sha256.Size224 ] )
	self.sha224 = sha256.Sum224( bytes )	// Why does Sum224 return a byte array?
	copy( bytes[ index : ] , self.sha224[ : ] )

	return bytes
}

// Or string
func ( self * Token ) String( ) string {
	return base64.RawStdEncoding.EncodeToString( self.Binary( ) )
}


