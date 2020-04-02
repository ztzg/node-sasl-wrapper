{
    "targets": [
        {
            "target_name": "node_sasl_wrapper",
            "sources": [ "node_sasl_wrapper.cc" ],
            "include_dirs": [
                "<!(node -e \"require('nan')\")"
            ],
            "cflags": [
                "-std=c++11"
            ],
            "link_settings": {
                "libraries": [
                    "-lsasl2"
                ]
            }
        }
    ],
}
