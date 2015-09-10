/*

Lua library for AES encryption. 

You need to obtain various files yourself to compile it. See below for details.

Author of this file: Nick Gammon
Date: 10th December 2004

For more information, see: 

  http://www.gammon.com.au/forum/bbshowpost.php?bbsubject_id=4988

  (C) Copyright Nick Gammon 2004. Permission to copy, use, modify, sell and
  distribute this software is granted provided this copyright notice appears
  in all copies. This software is provided "as is" without express or implied
  warranty, and with no claim as to its suitability for any purpose.


The AES implementations used here were written by Christophe Devine.

*/

#define LUA_BUILD_AS_DLL
#define LUA_LIB
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "aes.h"
#include "sha256.h"
#include <malloc.h>
#include <memory.h>
#include <stdlib.h>

#pragma comment( lib, "lua.lib" )
//#pragma comment( lib, "lualib.lib" )

/* Uncomment this to provide a "test" function */

/* #define TEST */

/* 

  For more information about the AES encryption, see:

    http://www.cr0.net:8040/code/crypto/

  Source needed in addition to this file is:

    aes.c
    aes.h

      For those two files, see: http://www.cr0.net:8040/code/crypto/aes/


    sha256.c
    sha256.h

      For those two files, see: http://www.cr0.net:8040/code/crypto/sha256/

    lua.h
    lauxlib.h

      For those two files, see: http://www.lua.org/download.html

  
  To link you also need:

    lua.lib
    lualib.lib

  To compile under Cygwin:
  
    gcc -shared -o aeslib.dll aes.c sha256.c aeslib.c lualib.lib lua.lib
    
*/

/*

  Usage: encrypted_text = encrypt (plaintext, key)
  
*/

static int encrypt (lua_State *L)
  {
  aes_context aes_ctx;
  sha256_context sha_ctx;
  unsigned char digest [32];
  unsigned char IV [16];  /* for cipher block chaining */
  unsigned char * buf;
  size_t offset;
  int i,
      lastn;

  /* get text to encrypt */
  size_t textLength;
  const unsigned char * text = luaL_checklstring (L, 1, &textLength);
    
  /* get key */
  size_t keyLength;
  const unsigned char * key = luaL_checklstring (L, 2, &keyLength);

  /* allocate memory to work in, rounded up to next 16 byte boundary
     plus 16 bytes for the IV */
  buf = (unsigned char *) malloc (textLength + 15 + 16);

  if (!buf)
    luaL_error (L, "not enough memory for encryption");

  /* generate random IV */
  for (i = 0; i < 16; i++)
    IV [i] = rand () & 0xFF;

  /* calculate how many bytes of final block are real data */
  lastn = textLength & 0x0F;

  /* use last 4 bits of IV to store length of final block */
  IV [15] &= 0xF0;
  IV [15] |= lastn;  /* number of bytes in final block */
  
  /* hash supplied key,and IV, to give a key for encryption */
  sha256_starts (&sha_ctx);
  sha256_update (&sha_ctx, IV, 16);
  sha256_update (&sha_ctx, (uint8 *) key, keyLength);
  sha256_finish (&sha_ctx, digest);

  /* use hashed supplied key (digest) for encryption */
  aes_set_key( &aes_ctx, digest, 256);
  
  /* copy initialization vector into output buffer */
  memcpy (buf, IV, 16);
  /* make sure all zero, in case not mod 16 bytes */
  memset (&buf [16], 0, textLength + 15);
  /* copy supplied text into it */
  memcpy (&buf [16], text, textLength);
  
  /* encrypt in blocks of 16 bytes (128 bits) */

  for (offset = 16; offset < (textLength + 16); offset += 16)
    {
    /* xor in the IV for this block */
    for (i = 0; i < 16; i++)
      buf [i + offset] ^= IV [i];
    aes_encrypt (&aes_ctx, &buf [offset], &buf [offset]);
    memcpy (IV, &buf [offset], 16);
    }

  /* push results */
  lua_pushlstring (L, buf, offset);

  free (buf);  /* don't need buffer any more */
  return 1;  /* number of result fields */
  } /* end of encrypt */

/*

  Usage: plaintext = decrypt (encrypted_text, key)
  
*/

static int decrypt (lua_State *L)
  {
  aes_context aes_ctx;
  sha256_context sha_ctx;
  unsigned char digest [32];
  unsigned char IV [16];  /* for cipher block chaining */
  unsigned char tmp [16];
  unsigned char * buf;
  size_t offset;
  int i,
      lastn;

  const unsigned char * text ;
  size_t textLength;

  const unsigned char * key;
  size_t keyLength;

  /* get text to decrypt */
  text = luaL_checklstring (L, 1, &textLength);
  
  if (textLength < 16)
    luaL_error (L, "encrypted data too short, must be at least 16 bytes");
  
  /* encrypted block starts with 16-byte initialization vector */
  memcpy (IV, text, 16);
  textLength -= 16;
  
  /* find how many bytes in final block */
  lastn = IV [15] & 0x0F;
  
  /* get key */
  key = luaL_checklstring (L, 2, &keyLength);

  /* hash supplied key ,and IV, to give a key for decryption */
  sha256_starts (&sha_ctx);
  sha256_update (&sha_ctx, IV, 16 );
  sha256_update (&sha_ctx, (uint8 *) key, keyLength);
  sha256_finish (&sha_ctx, digest);

  /* use hashed supplied key (digest) for decryption */
  aes_set_key( &aes_ctx, digest, 256);

  buf = (unsigned char *) malloc (textLength + 15);

  if (!buf)
    luaL_error (L, "not enough memory for decryption");

  /* make sure all zero, in case not mod 16 bytes */
  memset (buf, 0, textLength + 15);
  /* copy supplied text into it, skipping IV */
  memcpy (buf, &text [16], textLength);

  /* decrypt in blocks of 16 bytes (128 bits) */

  for (offset = 0; offset < textLength; offset += 16)
    {
    memcpy (tmp, &buf [offset], 16); /* this will be the IV next time */
    aes_decrypt (&aes_ctx, &buf [offset], &buf [offset]);
    for ( i = 0; i < 16; i++ )  /* xor in current IV */
      buf [offset + i] ^= IV [i];
    memcpy (IV, tmp, 16);    /* new IV */
    }

  /* trim final length */
  if (lastn)
    offset -= 16 - lastn;
  
  /* push results */
  lua_pushlstring (L, buf, offset);

  free (buf);  /* don't need buffer any more */
  return 1;  /* number of result fields */
  } /* end of decrypt */

#ifdef TEST
static int test (lua_State *L)
  {
  aes_context aes_ctx;
  sha256_context sha_ctx;
  unsigned char digest[32];
  unsigned char buf [16];
  unsigned char result1 [16];
  unsigned char result2 [16];
  
  memset (digest, 0, sizeof (digest));
  memset (buf, 0, sizeof (buf));

  aes_set_key( &aes_ctx, (uint8 *) digest, 256);
  aes_encrypt (&aes_ctx, buf, result1); 
  aes_encrypt (&aes_ctx, result1, result2); 
  
  lua_pushlstring (L, result1, sizeof (result1));
  lua_pushlstring (L, result2, sizeof (result2));
  
  /*
  Results should be: 
    DC95C078A2408989AD48A21492842087
    08C374848C228233C2B34F332BD2E9D3
    
  See "The Design of Rijndael" by Joan Daemen and Vincent Rijmen.
  Test vector results for block length 128, key length 256.
  
  */
  
  return 2;  /* number of result fields */
  } /* end of test */
#endif

/* table of operations */
static const struct luaL_reg aeslib [] = 
  {

  {"encrypt", encrypt},
  {"decrypt", decrypt},

#ifdef TEST
  {"test", test},
#endif

  {NULL, NULL}
  };

/* register library */

LUALIB_API int luaopen_aes(lua_State *L)
  {
  luaL_openlib(L, "aes", aeslib, 0);
  return 1;
  }

#include "lua.h"
#include "lauxlib.h"

#include <string.h>

#define MAX_BYTES 1024

unsigned char prime[MAX_BYTES], 
              generator[MAX_BYTES], 
              exponent[MAX_BYTES], 
              result[MAX_BYTES];

/* bytes = number of bytes in prime + 1 */
static int n, v, d, z, bytes;

static void a (unsigned char * x, unsigned char * y, int o)
{
  d = 0;
  for (v = bytes; v--;)
    {
      d += x[v] + y[v] * o;
      x[v] = d;
      d = d >> 8;
    }
}

static void s (unsigned char * x)
{
  for (v = 0; (v < bytes - 1) && (x[v] == prime[v]);)
    v++;
  if (x[v] >= prime[v])
    a (x, prime, -1);
}

static void r (unsigned char * x)
{
  d = 0;
  for (v = 0; v < bytes;)
    {
      d |= x[v];
      x[v++] = d / 2;
      d = (d & 1) << 8;
    }
}

static void M (unsigned char * x, unsigned char * y)
{
  unsigned char X[MAX_BYTES], Y[MAX_BYTES];
  memcpy (X, x, bytes);
  memcpy (Y, y, bytes);
  memset (x, 0, bytes);
  for (z = bytes * 8; z--;)
    {
    if (X[bytes - 1] & 1)
      {
        a (x, Y, 1);
        s (x);
      }
    r (X);
    a (Y, Y, 1);
    s (Y);
    }
}

static void fromhex (char *x, unsigned char * y)
{
  memset (y, 0, bytes);
  for (n = 0; x[n] > 0; n++)
    {
    for (z = 4; z--;)
      a (y, y, 1);
    x[n] |= 32;
    y[bytes - 1] |= x[n] - 48 - (x[n] > 96) * 39;
    }
}

static void output (lua_State * L, unsigned char * x)
{
char buff [MAX_BYTES * 2 + 1];
char * p = buff;

  for (n = 0; !x[n];)
    n++;
  for (; n < bytes; n++)
    p += sprintf (p, "%c%c", 48 + x[n] / 16 + (x[n] > 159) * 7,
      48 + (x[n] & 15) + 7 * ((x[n] & 15) > 9));
lua_pushstring (L, buff);
}

/* dh generator exponent prime */

int dh (lua_State * L)
{
unsigned char p [MAX_BYTES * 2], 
              g [MAX_BYTES * 2], 
              e [MAX_BYTES * 2];

const unsigned char * generatorText;
const unsigned char * exponentText;
const unsigned char * primeText;

  /* get generator */
  generatorText = luaL_checkstring (L, 1);
  if ((strlen (generatorText) / 2) > (MAX_BYTES - 1))
    luaL_error (L, "generator too long");
  strcpy (g, generatorText);

  /* get exponent */
  exponentText = luaL_checkstring (L, 2);
  if ((strlen (exponentText) / 2) > (MAX_BYTES - 1))
    luaL_error (L, "exponent too long");
  strcpy (e, exponentText);

  /* get prime */
  primeText = luaL_checkstring (L, 3);
  if ((strlen (primeText) / 2) > (MAX_BYTES - 1))
    luaL_error (L, "prime too long");
  strcpy (p, primeText);

  if (strlen (exponentText) > strlen (primeText))
    luaL_error (L, "exponent length > prime length");

  if (strlen (generatorText) > strlen (primeText))
    luaL_error (L, "generator length > prime length");
  
  // bytes in prime number
  bytes = ((strlen (primeText) + 1) / 2) + 1;

  fromhex (g, generator);
  fromhex (e, exponent);
  fromhex (p, prime);
  memset (result, 0, bytes);
  result[bytes - 1] = 1;
  for (n = bytes * 8; n--;)
    {
    if (exponent[bytes - 1] & 1)
      M (result, generator);
    M (generator, generator);
    r (exponent);
    }
  output (L, result);
  return 1;
}
 


You also need to add the dh function to the list of the functions exported to Lua:


/* table of operations */
static const struct luaL_reg aeslib [] = 
  {
  // CBC encrypting
  {"encrypt", encrypt},
  {"decrypt", decrypt},

  // Diffie-Hellman
  {"dh", dh},

#ifdef TEST
  {"test", test},
#endif

  {NULL, NULL}
  };