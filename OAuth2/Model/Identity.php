<?php

/**
 * @property Endpoint $Endpoint 
 * @property User $User
 */
    class Identity extends Oauth2AppModel
    {
        
        public $belongsTo = array(
            'Oauth2.Endpoint',
        );
        
        
        public function __construct($id = false, $table = null, $ds = null) {
            $this->belongsTo[] = Configure::read('Oauth2.userModel');
            parent::__construct($id, $table, $ds);
           
        }
    }
?>
