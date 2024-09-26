<?php

$message = array();             
$message_css = "";

function changePassword($user,$oldPassword,$newPassword,$newPasswordCnf){
  global $message;
  global $message_css;

  $server = "armg01";
  $port="389"; 
  $dn = "ou=Usuarios,dc=senac,dc=intra,dc=senac,dc=intra";
   
  error_reporting(0);
  ldap_connect($server, $port);
  $con = ldap_connect($server, $port);
  ldap_set_option($con, LDAP_OPT_PROTOCOL_VERSION, 3);
  
  // bind anon and find user by uid
  $user_search = ldap_search($con,$dn,"(|(uid=$user)(mail=$user))");
  $user_get = ldap_get_entries($con, $user_search); 
  $user_entry = ldap_first_entry($con, $user_search);
  $user_dn = ldap_get_dn($con, $user_entry);
  $user_id = $user_get[0]["uid"][0];
  $user_givenName = $user_get[0]["givenName"][0];
  $user_search_arry = array( "*", "ou", "uid", "mail", "passwordRetryCount", "passwordhistory" );
  $user_search_filter = "(|(uid=$user_id)(mail=$user))";
  $user_search_opt = ldap_search($con,$user_dn,$user_search_filter,$user_search_arry);
  $user_get_opt = ldap_get_entries($con, $user_search_opt); 
  $passwordRetryCount = $user_get_opt[0]["passwordRetryCount"][0];
  $passwordhistory = $user_get_opt[0]["passwordhistory"][0];
  
  //$message[] = "Username: " . $user_id;
  //$message[] = "DN: " . $user_dn;
  //$message[] = "Current Pass: " . $oldPassword;
  //$message[] = "New Pass: " . $newPassword;
  
  /* Start the testing */
  if ( $passwordRetryCount == 3 ) {
    $message[] = "Erro E101 - Sua conta está bloqueada!!!";
    return false;
  }
  if (ldap_bind($con, $user_dn, $oldPassword) === false) {
    $message[] = "Erro E101 - Nome de usuário ou senha está errado.";
    return false;
  }
  if ($newPassword != $newPasswordCnf ) {
    $message[] = "Erro E102 - Suas novas senhas  não correspondem!";
    return false;
  }
   $encoded_newPassword = "{SSHA}" . base64_encode( pack( "H*", sha1( $newPassword ) ) );
  $history_arr = ldap_get_values($con,$user_dn,"passwordhistory");
  if ( $history_arr ) {
       $message[] ="Erro E102 - Sua senha corresponde a uma  das 10 últimas senhas   que você usou, você deve vir com uma nova senha";
   return false;
  }
  if (strlen($newPassword) < 8 ) {
    $message[] = "Erro E103 - Sua nova senha é muito curta! <br/> Sua senha deve ter pelo menos 8 caracteres.";
    return false;
  }
  if (!preg_match("/[0-9]/",$newPassword)) {
    $message[] = "Erro E104 - Sua nova senha deve conter pelo menos um número.";
    return false;
  }
  if (!preg_match("/[a-zA-Z]/",$newPassword)) {
    $message[] = "Erro E105 - Sua nova senha deve conter pelo menos uma letra.";
    return false;
  }
  if (!preg_match("/[A-Z]/",$newPassword)) {
    $message[] = "Erro E106 - Sua nova senha deve conter pelo menos uma letra maiúscula.";
    return false;
  }
  if (!preg_match("/[a-z]/",$newPassword)) {
    $message[] = "Erro E107 - Sua nova senha deve conter pelo menos uma letra minúscula.";
    return false;
  }
  if (!$user_get) {
    $message[] = "Erro E200 -Unable to connect to server, você näo pode alterar sua senha, neste momento, desculpe.";
    return false; 
  }
 
  $auth_entry = ldap_first_entry($con, $user_search);
  $mail_addresses = ldap_get_values($con, $auth_entry, "mail");
  $given_names = ldap_get_values($con, $auth_entry, "givenName");
  $password_history = ldap_get_values($con, $auth_entry, "passwordhistory");
  $mail_address = $mail_addresses[0];
  $first_name = $given_names[0];
  
  /* And Finally, Change the password */
  $entry = array();
  $entry["userPassword"] = "$newPassword";
  
  if (ldap_modify($con,$user_dn,$entry) === false){
    $error = ldap_error($con);
    $errno = ldap_errno($con);
    $message[] = "E201 - Sua senha não pode ser a mudada entre em contato com o administrador.";
    $message[] = "$errno - $erro";
  } else { 
  $modf= "( echo {$_POST['novasenha1']} ; echo {$_POST['novasenha2']} ) | sudo /usr/sbin/smbldap-passwd {$_POST['usuario']}";
  $cmd_exec = shell_exec($modf);
    $message_css = "yes";
    mail($mail_address,"Aviso de alteracao de senha","caro $first_name"); 
    $message[] = "a senha para $user_id foi alterada.<br/>e já se encontra ativa<br/>"; 
  } 
} 

?>