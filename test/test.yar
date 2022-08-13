rule test
{
meta:
   author = "Ambash"

strings:
   $text_string = "Hello_world" fullword
condition:
   any of them
}