<?php

    class Oauth2AppController extends AppController
    {
        public $components = array('Session');
        
        public function __construct($request = null, $response = null) {
            parent::__construct($request, $response);
            if (Configure::read('Oauth2') == null)
            {
                throw new RuntimeException('Could not find OAuth2 configuration.');
            }
            
        }
         
         
    }
    
?>
