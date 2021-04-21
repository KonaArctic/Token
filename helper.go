package token

type any interface{ }

// https://stackoverflow.com/a/50346080/10958912
func mu( one ... any ) [ ]any {
	return one }

// https://stackoverflow.com/questions/26545883
func ternary( test bool, one any , two any ) any {
	if test {
		return one
	} else {
		return two } }


