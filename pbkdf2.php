<?php
    /** PBKDF2 Implementation (described in RFC 2898)
     *  See license at https://github.com/jeffsteinport/PBKDF2-Implementation
     * 
     *  @param string p password
     *  @param string s salt
     *  @param int c iteration count (use 1000 or higher)
     *  @param int kl derived key length
     *  @param string a hash algorithm (defaults to whirlpool)
     *
     *  Returns binary output that can be used as an encryption key.
     *  Use base64_encode to output plain text.
     *  @return string derived key
     *  
     *  Example:
     *  $key = pbkdf2("tk421","nD3$df9aSdVV0pr@dv**",5000,32);
     *  echo base64_encode($key);
     *  returns "0IMN1zq83irlxuhuRJLs6VlZEnB2m231QO5gTgSP0MI="
     * 
    */

function pbkdf2( $p, $s, $c, $kl, $a = 'whirlpool' ) {
     
    $hl = strlen(hash($a, null, true)); # Hash length
    $kb = ceil($kl / $hl);              # Key blocks to compute
    $dk = '';                           # Derived key
     
    # Create key
    for ( $block = 1; $block <= $kb; $block ++ ) {
     
        # Initial hash for this block
        $ib = $b = hash_hmac($a, $s . pack('N', $block), $p, true);
     
        # Perform block iterations
        for ( $i = 1; $i < $c; $i ++ )
     
            # XOR each iterate
            $ib ^= ($b = hash_hmac($a, $b, $p, true));
     
        $dk .= $ib; # Append iterated block
    }
     
    # Return derived key of correct length
    return substr($dk, 0, $kl);
}

?>
