// Public Access Client. Copyright (c) 2021 Kona Arctic. All rights reserved. ABSOLUTELY NO WARRANTY! https://akona.me mailto:arcticjieer@gmail.com
// HTTP CONNECT proxy server
package main
import "flag"
import "github.com/KonaArctic/Token"
import "os"

func main( ) {
	var err error
	var token token.Token
	os.Stderr.Write( [ ]byte( "Copyright (c) 2021 Kona Arctic. All rights reserved. ABSOLUTELY NO WARRANTY! https://akona.me mailto:arcticjieer@gmail.com\r\n" ) )

	// Parse arguments
	flag.Usage = func( ) {
		flag.CommandLine.Output( ).Write( [ ]byte( "For help and usage please contact software provider.\r\n" ) ) }
	service := flag.Uint( "service" , 0 , "" )
	flag.Uint64Var( & token.Ident , "ident" , 1 , "" )
	flag.Int64Var( & token.Expire , "expire" , 1 * 60 * 60 * 24 , "" )
	ladder := flag.Uint( "ladder" , 2 , "" )
	flag.Parse( )
	token.Service = uint16( * service )
	token.Ladder = uint32( * ladder )

	// Make token
	_ , err = os.Stdout.Write( [ ]byte( token.String( ) + "\r\n" ) )
	if err != nil {
		os.Stderr.Write( [ ]byte( "Fatal: " + err.Error( ) + "\r\n" ) )
		os.Exit( 1 )
	}

	return
}


