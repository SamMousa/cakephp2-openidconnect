<?php

    /**
     * @property Identity $Identity 
     */
    class Endpoint extends Oauth2AppModel 
    {
        public $hasMany = array(
            'Oauth2.Identity'
        );
    }

?>
