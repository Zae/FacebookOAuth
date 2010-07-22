<?

/*
* Ezra Pool (ezra@servicecut.nl) http://servicecut.nl
*
* @author Ezra Pool
* @version 0.0.1
*
* Adapted Abraham Williams TwitterOAuth class for use with FacebookOAuth
*/

/**
 * Facebook OAuth 2 class
 */
class FacebookOAuth {
  /* Verify SSL Cert. */
  public $verifypeer = FALSE;
  /* Decode returned json data. */
  public $decode_JSON = TRUE;
  /* Set connect timeout. */
  public $connecttimeout = 30;
  /* Set timeout default. */
  public $timeout = 30;
  /* Set the useragent. */
  public $useragent = "FacebookOAuth v0.0.1";
  /* Contains the last HTTP status code returned. */
  public $http_code;
  /* Contains the last HTTP headers returned. */
  public $http_info = array();
  /* Contains the last API call. */
  public $url;
  /* Contains last http_headers */
  public $http_header = array();
  
  /* Variables used internally by the class and subclasses */
  protected $client_id, $client_secret, $access_token;
  protected $callback_url;
  
  protected static $METHOD_GET = "GET";
  protected static $METHOD_POST = "POST";
  protected static $METHOD_DELETE = "DELETE";
  
  /**
   * Set API URLS
   */
  function AuthorizeUrl(){ return 'https://graph.facebook.com/oauth/authorize'; }
  function AccessTokenUrl(){ return 'https://graph.facebook.com/oauth/access_token'; }
  function GraphUrl(){ return 'https://graph.facebook.com/'; }  

  /**
   * construct FacebookOAuth object
   */
  function __construct($client_id, $client_secret, $callback_url = NULL, $access_token = NULL){
    $this->client_id = $client_id;
    $this->client_secret = $client_secret;
    $this->callback_url = $callback_url;
    $this->access_token = $access_token;
  }
  
  /**
   * Get the authorize URL
   *
   * @returns a string
   */
  public function getAuthorizeUrl($scope=NULL){
    $authorizeUrl = $this->AuthorizeUrl();
    $authorizeUrl .= "?client_id=".$this->client_id;
    if(!empty($this->callback_url)){
      $authorizeUrl .= "&redirect_uri=".$this->callback_url;
    }
    if(is_array($scope)){
      $authorizeUrl .= "&scope=".implode(",", $scope);
    }
    return $authorizeUrl;
  }
  
  /**
   * Exchange verify code for an access token
   *
   * @returns string access token
   */
  public function getAccessToken($code){
    $accessTokenUrl = $this->AccessTokenUrl();
    $accessTokenUrl .=  "?client_id=".$this->client_id.
                        "&client_secret=".$this->client_secret.
                        "&code=".$code;
    if(!empty($this->callback_url)){
      $accessTokenUrl .= "&redirect_uri=".$this->callback_url;
    }
    $contents = $this->http($accessTokenUrl, self::$METHOD_GET);
    
    preg_match("/^access_token=(.*)$/i", $contents, $matches);
    return $this->access_token = $matches[1];
  }
  
  /**
   * GET wrapper for oAuthRequest.
   */
  public function get($location){
    $url = $this->GraphUrl();
    $url .= $location;
    if(!empty($this->access_token)){
      $url .= "?access_token=".$this->access_token;
    }
    $response = $this->http($url, self::$METHOD_GET);
    return $this->decode_JSON ? json_decode($response) : $response;
  }
  
  /**
   * POST wrapper for oAuthRequest.
   */
  public function post($location, $postfields = array()){
    $url = $this->GraphUrl();
    $url .= $location;
    if(!empty($this->access_token)){
      $postfields["access_token"] = $this->access_token;
    }
    $response = $this->http($url, self::$METHOD_POST, $postfields);
    return $this->decode_JSON ? json_decode($response) : $response;
  }
  
  /**
   * DELETE wrapper for oAuthReqeust.
   */
  public function delete($location, $postfields = array()){
    $url = $this->GraphUrl();
    $url .= $location;
    $postfields = array();
    if(!empty($this->access_token)){
      $postfields["access_token"] = $this->access_token;
    }
    $response = $this->http($url, self::$METHOD_DELETE, $postfields);
    return $this->decode_JSON ? json_decode($response) : $response;
  }

  /**
   * Make an HTTP request
   *
   * @return API results
   */
  private function http($url, $method = "GET", $postfields=NULL){
    $this->http_info = array();
    $handle = curl_init();
    /* Curl settings */
    curl_setopt($handle, CURLOPT_HEADER, FALSE);
    curl_setopt($handle, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($handle, CURLOPT_HTTPHEADER, array('Expect:'));
    curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, $this->verifypeer);
    curl_setopt($handle, CURLOPT_CONNECTTIMEOUT, $this->connecttimeout);
    curl_setopt($handle, CURLOPT_TIMEOUT, $this->timeout);
    curl_setopt($handle, CURLOPT_USERAGENT, $this->useragent);
    curl_setopt($handle, CURLOPT_HEADERFUNCTION, array($this, 'getHeader'));
    
    switch($method){
      case self::$METHOD_POST:
        curl_setopt($handle, CURLOPT_POST, TRUE);
        if (!empty($postfields)) {
          curl_setopt($handle, CURLOPT_POSTFIELDS, $postfields);
        }
        break;
      case self::$METHOD_DELETE:
        curl_setopt($handle, CURLOPT_CUSTOMREQUEST, 'DELETE');
        if (!empty($postfields)){
          $url .= "?".implode("&", $postfields);
        }
        break;
    }
    curl_setopt($handle, CURLOPT_URL, $url);
    $response = curl_exec($handle);
    $this->http_code = curl_getinfo($handle, CURLINFO_HTTP_CODE);
    $this->http_info = array_merge($this->http_info, curl_getinfo($handle));
    $this->url = $url;
    curl_close($handle);
    return $response;
  }
  
  /**
   * Get the header info to store.
   */
  function getHeader($ch, $header) {
    $i = strpos($header, ':');
    if (!empty($i)) {
      $key = str_replace('-', '_', strtolower(substr($header, 0, $i)));
      $value = trim(substr($header, $i + 2));
      $this->http_header[$key] = $value;
    }
    return strlen($header);
  }
}

?>