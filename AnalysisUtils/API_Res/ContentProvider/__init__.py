'''
The mappings in this package are constructed as JSON dicts of the form:
permission:
    {
        "type" : r|w|rw,
        "uri" : URI prefix|code constant
    }

URI prefixes are considered for the case where a fixed URI is used, while the constants are strings from different SDK
classes that also can be used to reference a URI
'''