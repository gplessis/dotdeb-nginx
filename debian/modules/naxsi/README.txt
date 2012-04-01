  _   _                _ 
 | \ | | __ ___  _____(_)
 |  \| |/ _` \ \/ / __| |
 | |\  | (_| |>  <\__ \ |
 |_| \_|\__,_/_/\_\___/_|
 v0.44

|--{ Contents }----------------------------------------------------------------|

Contents :
* naxsi_src/ : naxsi's source code. Add --add-module=path/to/naxsi_src to 
  compile nginx with naxsi.

* naxsi_config/ : naxsi sample config. naxsi_core.rules : naxsi core rules. 
  default_location_config.example example scoring configuration with learning 
  mode. see wiki at naxsi.googlecode.com for more details.

* contrib/ : tools dedicated to make your life easier : learning daemon.
  * naxsi-ui/nx_intercept.py : naxsi's learning daemon, listen by default on 
    port 8000. use sql_id to setup MySQL configuration.
  * naxsi-ui/nx_extract.py : naxsi's whitelist rules generator, listen by 
    default on port 8081. use sql_id to setup MySQL configuration.
  * fp-reporter : contains a sample php page asking for a captcha before sending
    an email when an exception is catched.
  * rules_generator : old learning daemon / whitelist rules generator.

See naxsi.googlecode.com for details.
