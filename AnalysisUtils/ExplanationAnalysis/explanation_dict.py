basic_terms = [
    "access",
    "permission",
    "require",
    "allow",
    "need"
]

perm_specific_terms = {
    "android.permission.READ_CONTACTS": ["read", "contact", "import"],
    "android.permission.WRITE_CONTACTS": ["write", "contact", "import", "export", "create", "manage"],
    "android.permission.READ_CALENDAR" : ["read", "calendar", "event", "date", "meeting"],
    "android.permission.WRITE_CALENDAR" : ["write", "calendar", "event", "date", "meeting", "import", "export", "manage"],
    "android.permission.SEND_SMS" : ["send", "sms", "message"],
    "android.permission.RECEIVE_SMS" : ["receive", "sms", "message"],
    "android.permission.READ_SMS" : ["read", "sms", "message"],
    "android.permission.RECEIVE_WAP_PUSH" : ["receive", "wap", "push", "message"],
    "android.permission.RECEIVE_MMS" : ["receive", "mms", "message"],
    "android.permission.READ_CELL_BROADCASTS" : ["cell broadcast", "cell information"],
    "android.permission.READ_EXTERNAL_STORAGE" : ["read", "external storage", "file", "media", "backup"],
    "android.permission.WRITE_EXTERNAL_STORAGE" : ["write", "create", "modify", "external storage", "file", "media", "backup"],
    "android.permission.ACCESS_FINE_LOCATION" : ["precise", "location", "gps"],
    "android.permission.ACCESS_COARSE_LOCATION" : ["coarse", "approximate", "location", "gps"],
    "android.permission.READ_PHONE_STATE" : ["phone state", "phone number", "cellular", "status", "account"],
    "android.permission.CALL_PHONE" : ["call", "phone", "dialer"],
    "android.permission.READ_CALL_LOG" : ["read", "call log"],
    "android.permission.WRITE_CALL_LOG" : ["write", "call log"],
    "com.android.voicemail.permission.ADD_VOICEMAIL" : ["add", "create", "import", "modify", "voicemail"],
    "android.permission.USE_SIP" : ["sip", "session initiation protocol", "internet telephony", "video conference"],
    "android.permission.PROCESS_OUTGOING_CALLS" : ["outgoing", "call", "process", "manage", "redirect", "abort", "dial", "handle"],
    "android.permission.RECORD_AUDIO" : ["record", "audio", "microphone", "voice"],
    "android.permission.CAMERA" : ["camera", "photo", "picture", "video", "record"],
    "android.permission.BODY_SENSORS" : ["body sensor", "measure"],
    "android.permission.GET_ACCOUNTS" : ["list", "accounts", "account service"],
    "com.android.launcher.permission.INSTALL_SHORTCUT" : ["install", "create", "shortcut", "launcher"],
    "com.android.launcher.permission.UNINSTALL_SHORTCUT" : ["uninstall","remove", "shortcut", "launcher"],
    "com.android.email.permission.READ_ATTACHMENT" : ["attachment", "email"],
    "android.permission.READ_TV_LISTINGS" : []
}