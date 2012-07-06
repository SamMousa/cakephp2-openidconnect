<?php

    App::uses('CakeSession', 'Model/Datasource');
    App::uses('Security' , 'Utility');
    App::uses('HttpSocket', 'Network/Http');
    App::uses('CakeRequest', 'Network');
    class OAuth2Socket extends HttpSocket 
    {

        private $version = '2.25'; // This library implements OAuth 2 draft 25.

        /**
         * Contains information for the known endpoints.
         * @var array
         */
        private $options = array(
            'redirect_uri' => null,
            'endpoints' => array(
                'example' => array(
                    'client_id' => null,
                    'client_secret' => null,
                    'endpoint' => null
                )
            )
        );
        
        /**
         * The currently "active" endpoint. 
         * @var string
         */
        private $endpoint;
        
        /** 
         * Constructor
         * @param array $options 
         */
        public function __construct(array $options = array())
        {
            parent::__construct();
            
            $this->options = array_merge($this->options, $options);
        }
        
        /*
         * @return string Creates a verifiable state value. 
         */
        private function generateState($timestamp = null)
        {
            // The session id is used as a basis for the state.
            if ($timestamp == null)
            {
                $timestamp = date(DATE_ATOM);
            }
            $state = $timestamp . Security::hash(session_id() . $timestamp);
            return $state;
        }
        
        /**
         * Checks the state signature for correctness and checks the time.
         * @return boolean True if the state is valid.
         */
        static private function isValidState($state = '')
        {
            $timestamp = subst($state, 0, 25);
            if (strcmp(generateState($timestamp), $state) === 0)
            {
                return true;
            }
            return false;
        }
        
        /**
         *
         * @return boolean 
         */
        private function client_id($endpoint)
        {
            if (isset($this->endpoint) 
                    && isset($this->options['endpoints'][$this->endpoint]))
            {
                return $this->options['endpoints'][$this->endpoint]['client_id'];
            }
            return false;
        }
        
        private function redirect_uri()
        {
            if (isset($this->options['redirect_uri']))
            {
                return $this->options['redirect_uri'];
            }
            return false;
        }

        
        private function token_url()
        {
           if (isset($this->endpoint) 
                    && isset($this->options['endpoints'][$this->endpoint]))
            {
                return $this->options['endpoints'][$this->endpoint]['token_url'];
            }
            return false;
        }
        private function token_method()
        {
           if (isset($this->endpoint) 
                    && isset($this->options['endpoints'][$this->endpoint]['token_method']))
            {
                return $this->options['endpoints'][$this->endpoint]['token_method'];
            }
            else
            {
                return 'POST';
            }
            
        }
        private function checkid_url()
        {
           if (isset($this->endpoint) 
                    && isset($this->options['endpoints'][$this->endpoint]))
            {
                return $this->options['endpoints'][$this->endpoint]['checkid_url'];
            }
            return false;
        }
        
        private function client_secret()
        {
            if (isset($this->endpoint) 
                    && isset($this->options['endpoints'][$this->endpoint]))
            {
                return $this->options['endpoints'][$this->endpoint]['client_secret'];
            }
            return false;
        }
        /**
         * This function generates a URL where for the user.
         * @param string[] $scope Requested scopes.
         * @return string URL for the user to grant access.
         */
        public function getAuthorizationCodeURL(array $scope,  array $endpoint, array $options = array())
        {
            if (isset($endpoint['Endpoint']))
            {
                $endpoint = $endpoint['Endpoint'];
            }
            $_options = array(
                'client_id' => $endpoint['client_id'] ,
                'redirect_uri' => $this->redirect_uri(),
                'response_type' => 'code',
                'state' => $this->generateState(),
                'scope' => implode(' ', $scope),
                // Google
                //'approval_prompt' => 'force',
                // Facebook
                //'auth_type' => 'reauthenticate',
                //'display' => 'page', // page | popup | touch
                // Not used yet.
                //'nonce' => 'Sam is gaaf'
            );
            $options = array_merge($_options, $options);
            return $endpoint['auth_url'] . Router::queryString($options);
        }
        
        /**
         * Checks if the request could be an OAuth request.
         * @param CakeRequest $request 
         * @returns boolean True if it could be.
         */
        static public function isOAuth(CakeRequest $request)
        {
            if (isset($request->query['state']) && (
                isset($request->query['error']) 
                    || isset($request->query['code'])))
            {
                return self::isValidState($request->query['state']);
            }
            return false;
        }
        
        /**
         * This function checks the URL for a valid state variable and returns the authorization code sent by the user agent.
         * @param CakeRequest $request
         * @return string Authorization code
         */
        public function parseAuthorizationResult(CakeRequest $request)
        {
            $result = array();
            if (isset($request->query['state']))
            {
                // Assume it's an OAuth response; validate state variable.
                $timeStamp = substr($request->query['state'], 0, 25);
                
                $state = $timeStamp . Security::hash(session_id() . $timeStamp);
                if (strcmp($state, $request->query['state']) == 0 && isset($request->query['code']))
                {
                    // State is valid.
                    return $request->query['code'];
                }
                
            }
            return false;
        }
        
        /**
         * This function retrieves the access token given the authorization code.
         * @param array $endpoint
         * @param string $code
         * @return type 
         */
        public function getAccessToken($code, array $endpoint, array $options = array())
        {
            $_options = array(
                'code' => $code,
                'client_id' => $endpoint['client_id'],
                'client_secret' => $endpoint['client_secret'],
                'redirect_uri' => $this->redirect_uri(),
                'grant_type' => 'authorization_code'
            );
            
            $options = array_merge($_options, $options);
            if (!empty($code) && is_string($code) && strlen($code) > 0)
            {
                /* @var $response CakeResponse */
                $response = $this->post($endpoint['token_url'], $options);
                return $this->decode($response->body);
            }
            return '';
        }
        
        /**
         * Decodes the access token response.
         * This may be either a query string or a JWT
         * @param string $body 
         */
        private function decode($body)
        {
            $result = json_decode($body, true);
            if ($result === null)
            {
                parse_str($body, $result);
            }
            return $result;
            
            
        }
        public function checkid($id_token, $url)
        {
            $request = array();
            
            $response = parent::get($url, array('id_token'=> $id_token), $request);
            return json_decode($response->body, true);
        
        }
        
        public function get($accessToken, $uri, $query = array(), $request = array()) 
        {
            $query = array();
            // For now we will put the access token in the header AND the request.
          
            $request['header']['Authorization'] = "Bearer $accessToken";
            //$query['access_token'] = $accessToken;
            $response = parent::get($uri, $query, $request);
            return json_decode($response->body, true);
            
        }
        
    }
    
?>
