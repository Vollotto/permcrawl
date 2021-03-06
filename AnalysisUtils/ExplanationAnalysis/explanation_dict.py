'''
Contains a list of basic permission-related terms and permission-specific keyword lists

Specific keyword lists can be queried by referencing
    perm_specific_terms[<permission name>]
'''
basic_terms = [
    "access",
    "permission",
    "require",
    "allow",
    "need",
    "grant"
]

perm_specific_terms = {
    "android.permission.READ_CONTACTS": ["read", "contact", "import", "synchronize", "synchronization", "friend"],
    "android.permission.WRITE_CONTACTS": ["write", "contact", "import", "export", "create", "manage", "synchronize",
                                          "synchronization", "friend"],
    "android.permission.READ_CALENDAR" : ["read", "calendar", "event", "date", "meeting", "schedule", "agenda", "task",
                                          "import"],
    "android.permission.WRITE_CALENDAR" : ["write", "create", "calendar", "event", "date", "meeting", "export","manage",
                                           "schedule", "agenda", "task"],
    "android.permission.SEND_SMS" : ["send", "sms", "message"],
    "android.permission.RECEIVE_SMS" : ["receive", "sms", "message"],
    "android.permission.READ_SMS" : ["read", "sms", "message"],
    "android.permission.RECEIVE_WAP_PUSH" : ["receive", "wap", "push", "message"],
    "android.permission.RECEIVE_MMS" : ["receive", "mms", "message"],
    "android.permission.READ_CELL_BROADCASTS" : ["cell broadcast", "cell information"],
    "android.permission.READ_EXTERNAL_STORAGE" : ["read", "storage", "file", "media", "backup", "sdcard"],
    "android.permission.WRITE_EXTERNAL_STORAGE" : ["write", "create", "modify", "storage", "file", "media",
                                                   "backup", "sdcard"],
    "android.permission.ACCESS_FINE_LOCATION" : ["precise", "location", "gps", "track"],
    "android.permission.ACCESS_COARSE_LOCATION" : ["coarse", "approximate", "location", "gps", "track"],
    "android.permission.READ_PHONE_STATE" : ["phone state", "phone number", "cellular", "status", "account"],
    "android.permission.CALL_PHONE" : ["call", "phone", "dialer"],
    "android.permission.READ_CALL_LOG" : ["read", "call log"],
    "android.permission.WRITE_CALL_LOG" : ["write", "call log"],
    "com.android.voicemail.permission.ADD_VOICEMAIL" : ["add", "create", "import", "modify", "voicemail"],
    "android.permission.USE_SIP" : ["sip", "session initiation protocol", "internet telephony", "video conference"],
    "android.permission.PROCESS_OUTGOING_CALLS" : ["outgoing", "call", "process", "manage", "redirect", "abort",
                                                   "dial", "handle"],
    "android.permission.RECORD_AUDIO" : ["record", "audio", "microphone", "voice", "speak", "speech", "mic",
                                         "interact", "sound", "talk"],
    "android.permission.CAMERA" : ["camera", "photo", "picture", "video", "record"],
    "android.permission.BODY_SENSORS" : ["body sensor", "measure"],
    "android.permission.GET_ACCOUNTS" : ["list", "accounts", "account service"],
    "com.android.launcher.permission.INSTALL_SHORTCUT" : ["install", "create", "shortcut", "launcher"],
    "com.android.launcher.permission.UNINSTALL_SHORTCUT" : ["uninstall","remove", "shortcut", "launcher"],
    "com.android.email.permission.READ_ATTACHMENT" : ["attachment", "email"],
}