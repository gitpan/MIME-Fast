/**
* g_mime_message_set_date_from_string: Set the message sent-date
* @message: MIME Message
* @string: A string of date
* 
* Set the sent-date on a MIME Message.
**/
       
void
g_mime_message_set_date_from_string (GMimeMessage *message, const char *string) {
  time_t date;
  int offset = 0;

  date = g_mime_utils_header_decode_date (string, &offset);
  g_mime_message_set_date (message, date, offset); 
}

static const char *
g_strstrbound (const char *haystack, const char *needle, const char *end)
{
        gboolean matches = FALSE;
        const char *ptr;
        guint nlen;
        
        nlen = strlen (needle);
        ptr = haystack;
        
        while (ptr + nlen <= end) {
                if (!strncmp (ptr, needle, nlen)) {
                        matches = TRUE;
                        break;
                }
                ptr++;
        }
        
        if (matches)
                return ptr;
        else
                return NULL;
}


static const char *
find_header_part_end (const char *in, guint inlen)
{
        const char *pch;
        const char *hdr_end = NULL;

        g_return_val_if_fail (in != NULL, NULL);

        if (*in == '\n') /* if the beginning is a '\n' there are no content headers */
                hdr_end = in;
        else if ((pch = g_strstrbound (in, "\n\n", in+inlen)) != NULL)
                hdr_end = pch;
        else if ((pch = g_strstrbound (in, "\n\r\n", in+inlen)) != NULL)
                hdr_end = pch;

        return hdr_end;
}

