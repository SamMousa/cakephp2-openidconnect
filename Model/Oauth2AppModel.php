<?php
    
    class Oauth2AppModel extends AppModel
    {
        public $actsAs = array(
            'Containable'
        );
        
        public function __construct($id = false, $table = null, $ds = null) 
        {
            parent::__construct($id, $table, $ds);
            
        }
        


    }
?>
