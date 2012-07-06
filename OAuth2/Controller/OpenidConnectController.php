<?php

    /**
    * @property Identity $Identity
    */

    class OpenidConnectController extends Oauth2AppController 
    {
        public $uses = array('Oauth2.Identity');
        
        private function _getSocket()
        {
            /**
             * @todo Change this when Router::url adds support for https. 
             */
            $url = Router::url('callback', true);
            $url = str_replace('http://', 'https://', $url);
            
            $options['redirect_uri'] = $url;
            return new OAuth2Socket($options);
            
        }
        public function login($id = false)
        {
            if (is_numeric($id))
            {
                $endpoint_id = $id;
            }
            elseif ($this->request->data('Identity.endpoint_id') != null)
            {
                $endpoint_id = intVal($this->request->data('Identity.endpoint_id'));
            }
            if (isset($endpoint_id))
            {
                // Create URL for redirection.
                $s = $this->_getSocket();
                // Scope is still provider specific.
                // This should be fixed when Openid Connect gains more acceptance.

                switch ($endpoint_id)
                {
                    case 1: // Google
                    case 5:
                        $scope = array(
                            'https://www.googleapis.com/auth/userinfo.email',
                            'https://www.googleapis.com/auth/userinfo.profile'                               
                        );
                        break;
                    case 2: // Facebook
                        $scope = array(
                            'email'
                        );
                        break;
                    case 4: // Windows Live
                        $scope = array(
                            'wl.basic',
                            'wl.emails'
                        );
                        break;
                    default:
                        $scope = array('openid', 'email');
                }
                $endpoint = $this->Identity->Endpoint->find('first', array(
                    'conditions' => array('id' => $endpoint_id)
                ));
                $this->Session->write('Oauth2.OpenidConnect', $endpoint);

                // Redirect user to URL.
                $url = $s->getAuthorizationCodeURL($scope, $endpoint);

                $this->redirect($url);



            }
            else
            {
                $endpoints = $this->Identity->Endpoint->find('list');
                $this->set(compact('endpoints'));
            }
        }
        
        /**
         * Endpoint to which the User Agent is redirected after authentication by the
         * oauth 2 endpoint.
         */
        public function callback()
        {
            if ($this->Session->check('Oauth2.OpenidConnect.Endpoint'))
            {
                $s = $this->_getSocket();
                if (($authorizationCode = $s->parseAuthorizationResult($this->request)) !== false)
                {
                    
                    $token = $s->getAccessToken($authorizationCode, $this->Session->read('Oauth2.OpenidConnect.Endpoint'));
                    
                    
                    // If we have a Checkid endpoint we use it to verify the token.
                    // Since we use the Authorization code Flow this is not required for security; crypto verification is an alternative.
                    if ($this->Session->check('Oauth2.OpenidConnect.Endpoint.checkid_url'))
                    {
                        $check = $s->checkid($token['id_token'], $this->Session->read('Oauth2.OpenidConnect.Endpoint.checkid_url'));
                        //debug($check);
                    }
                    // Get UserInfo.
                    if ($this->Session->check('Oauth2.OpenidConnect.Endpoint.userinfo_url'))
                    {
                        $userInfo = $s->get($token['access_token'], $this->Session->read('Oauth2.OpenidConnect.Endpoint.userinfo_url'));
                        //debug($userInfo);
                        // Get the user identity.
                        $userIdentity = isset($userInfo['id']) ? $userInfo['id'] : $userInfo['user_id'];
                        
                        // Get the emailaddress.
                        $email = isset($userInfo['email']) ? $userInfo['email'] : $userInfo['emails']['preferred'];
                         
                        // Check if the emailaddress needs to be verified.
                        $verified = isset($userInfo['verified']) ? $userInfo['verified'] : $userInfo['verified_email'];
                        
                        // Get the name.
                        $name = $userInfo['name'];
                        
                        // Check if the identity is known.
                        if (($identity = $this->Identity->find('first', array(
                            'conditions' => array(
                                'identity' => $userIdentity,
                                'endpoint_id' => $this->Session->read('Oauth2.OpenidConnect.Endpoint.id')
                            ),
                            'contain' => false
                        ))) !== false)
                        { // Identity is known.
                            $userId = $identity['Identity']['user_id'];
                        }
                        elseif ($email != null)
                        { // Identity is not known.
                            if (($user = $this->Identity->User->find('first', array(
                                'conditions' => array(
                                    'email' => $email
                                ),
                                'contain' => false
                            ))) !== false)
                            { // Email is known.
                                $userId = $user['User']['id'];
                            }
                            else
                            { // Email is not known.
                                $user = array('User' => array(
                                    'email' => $email,
                                    'name' => $name,
                                    'group_id' => 7,
                                    'active' => date('Y-m-d H:i:s'),
                                ));
                                $this->Identity->User->create();
                                if ($this->Identity->User->save($user))
                                {
                                    $userId = $this->Identity->User->id;
                                }
                            }
                            
                            if (isset($userId))
                            {
                                $identity = array('Identity' => array(
                                    'endpoint_id' => $this->Session->read('Oauth2.OpenidConnect.Endpoint.id'),
                                    'identity' => $userIdentity,
                                    'user_id' => $userId

                                ));
                                $this->Identity->create();
                                $this->Identity->save($identity);
                            }
                        }
                        if (isset($userId))
                        {
                            $this->Session->write('SessionLogin.User.id', intval($userId));
                            if (Configure::read('debug') == 2)
                            {
                                debug('Login success');
                            }
                            else
                            {
                                $this->redirect('http://survey.effectiefonderzoek.nl/beheer/users/sessionlogin');
                            }
                        }    
                    }
                    
                }
            } 
           if (Configure::read('debug') == 2)
            {
                debug($this->params['url']);
            }
            else
            {
                $this->redirect('http://survey.effectiefonderzoek.nl/beheer/users/login');
	    }
        }
    }
?>
