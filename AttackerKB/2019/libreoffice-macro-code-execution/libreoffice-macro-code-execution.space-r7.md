---
title: LibreOffice Macro Code Execution
author: space-r7
score: 1
topic_attacker_value: 4
topic_exploitability: 3
topic_disclosure_date: '2019-03-25T18:29:00'
created: '2019-05-09T17:57:36.8952'
revision_date: '2020-03-15T04:22:22.595044'
assessment_id: 1f1343c4-1705-4aeb-8df4-0c7a2db938d5
topic_id: d63a8152-ff88-423f-b246-de1cf9dee44e
topic_short_id: 5ezdasgubL
topic_slug: libreoffice-macro-code-execution
akb_topic_url: https://attackerkb.com/topics/5ezdasgubL/libreoffice-macro-code-execution
akb_assessment_url: https://attackerkb.com/topics/5ezdasgubL/libreoffice-macro-code-execution#1f1343c4-1705-4aeb-8df4-0c7a2db938d5
author_ratings:
  attacker-value: 4
  confidence-in-ratings: 3
  effort-to-develop-exploit: 3
  exploitability: 3
  urgent-to-patch: 5
  used-successfully: 5
---

# LibreOffice Macro Code Execution

*Assessment by space-r7, archived from [AttackerKB](https://attackerkb.com/topics/5ezdasgubL/libreoffice-macro-code-execution#1f1343c4-1705-4aeb-8df4-0c7a2db938d5).*

---

## Details

LibreOffice offers the ability to create program events that when triggered, will execute a macro. LibreOffice gives the option to develop custom macros or select a macro from a list of scripts included with the installation. The included macros are written in a variety of languages, including Python.
Creating a mouse over event that will execute a macro upon hovering over a hyperlink will result in XML that looks similar to this:

`<script:event-listener script:language="ooo:script" script:event-name="dom:mouseover" xlink:href="vnd.sun.star.script:pythonSamples|TableSample.py$createTable?language=Python&amp;location=share" xlink:type="simple"/>`

Alex Inführ discovered that a directory traversal vulnerability exists in the `xlink:href` attribute, allowing the ability to call functions (with its arguments) of other Python scripts included with the LibreOffice installation. The `tempfilepager()` function in `program/python-core-3.5.5/lib/pydoc.py` was found to both accept function arguments and pass those arguments to `os.system()`, allowing for arbitrary code execution.

```
def tempfilepager(text, cmd):
    """Page through text by invoking a program on a temporary file."""
    import tempfile
    filename = tempfile.mktemp()
    with open(filename, 'w', errors='backslashreplace') as file:
        file.write(text)
    try:
        os.system(cmd + ' "' + filename + '"')
    finally:
        os.unlink(filename)
```



The directory traversal vulnerability stems from how the URI in the `xlink:href` attribute is converted to the  actual URI of the Python script on disk. The function that does this conversion is located in `program/pythonscript.py` called `scriptURI2StorageUri()`.

```
def scriptURI2StorageUri( self, scriptURI ):
    try:
        myUri = self.m_uriRefFac.parse(scriptURI)
        ret = self.m_baseUri + "/" + myUri.getName().replace( "|", "/" )
        log.debug( "converting scriptURI="+scriptURI + " to storageURI=" + ret )
        return ret
    except UnoException as e:
        log.error( "error during converting scriptURI="+scriptURI + ": " + e.Message)
        raise RuntimeException( "pythonscript:scriptURI2StorageUri: " +e.getMessage(), None )
    except Exception as e:
        log.error( "error during converting scriptURI="+scriptURI + ": " + str(e))
        raise RuntimeException( "pythonscript:scriptURI2StorageUri: " + str(e), None )
```

The `scriptURI` variable passed to the function is the attacker-controlled path. In the line `ret = self.m_baseUri + "/" + myUri.getName().replace( "|", "/" )`, the local scripts path gets built. `m_baseUri`, the base installation path, gets concatenated with a `/` and the controllable path (with `vnd.sun.star.script:` removed) after any `|` characters are replaced with `/`.

The final storage URI `ret` would look like this on a Linux LibreOffice installation:

`file:///opt/libreoffice6.1/share/Scripts/python/../../../../program/python-core-3.5.5/lib/pydoc.py$tempfilepager(ARG1, ARG2)`
