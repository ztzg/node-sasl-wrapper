{
    "targets": [
        {
            "target_name": "node_sasl_wrapper",
            "sources": [ "node_sasl_wrapper.cc" ],
            "include_dirs": [
 	 	"<!(node -e \"require('nan')\")"
	    ],
            "link_settings": {
                "libraries": [
                    "-lsasl2"
                ]
            }
        }
    ],
}
