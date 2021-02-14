package token
import "net/http"

// Checks Authorization headers
func Authorization( response http.ResponseWriter, request * http.Request ) [ ]Token {
	var tokens [ ]Token

	if ( request.Header[ "Authorization" ] == nil || len( request.Header[ "Authorization" ] ) == 0 ) {
		response.WriteHeader( http.StatusUnauthorized )
		response.Write( [ ]byte( "TOKEN: cant find" ) )
		response.( http.Flusher ).Flush( )
		panic( "TOKEN: cant find" )
	}

	for _ , header := range request.Header[ "Authorization" ] {
		token , err := Parse( header )
		if err != nil {
			if err.Error( ) == "TOKEN: Cant decode" {
				response.WriteHeader( http.StatusBadRequest )
			} else {
				response.WriteHeader( http.StatusUnauthorized )
			}
			response.Write( [ ]byte( err.Error( ) ) )
			response.( http.Flusher ).Flush( )
			panic( err.Error( ) )
		}
		tokens = append( tokens , token )
	}

	return tokens
}


