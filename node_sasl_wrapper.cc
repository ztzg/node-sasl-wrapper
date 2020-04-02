#include "node_sasl_wrapper.h"

using v8::FunctionTemplate;

Nan::Persistent<v8::Function> SaslWrapper::constructor;

NAN_MODULE_INIT(SaslWrapper::Init) {
  v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
  tpl->SetClassName(Nan::New("SaslWrapper").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "connect", Connect);
  Nan::SetPrototypeMethod(tpl, "clientStart", ClientStart);
  Nan::SetPrototypeMethod(tpl, "clientStep", ClientStep);

  constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
  Nan::Set(target, Nan::New("SaslWrapper").ToLocalChecked(), Nan::GetFunction(tpl).ToLocalChecked());
}

SaslWrapper::SaslWrapper() : _conn(nullptr) {
}

SaslWrapper::~SaslWrapper() {
  if (_conn)
    sasl_dispose(&_conn);
}

NAN_METHOD(SaslWrapper::New) {
  if (info.IsConstructCall()) {
    SaslWrapper *obj = new SaslWrapper();
    obj->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  } else {
    // ??? TODO(dd): Figure this out
    const int argc = 1;
    v8::Local<v8::Value> argv[argc] = {info[0]};
    v8::Local<v8::Function> cons = Nan::New(constructor);
    info.GetReturnValue().Set(Nan::NewInstance(cons, argc, argv).ToLocalChecked());
  }
}

// TODO(diederen): This comes from the kerberos module; figure out
// license implications or rewrite.
static std::string StringOptionValue(v8::Local<v8::Object> options, const char* _key) {
  Nan::HandleScope scope;
  v8::Local<v8::String> key = Nan::New(_key).ToLocalChecked();
  if (options.IsEmpty() || !Nan::Has(options, key).FromMaybe(false)) {
    return std::string();
  }

  v8::Local<v8::Value> value = Nan::Get(options, key).ToLocalChecked();
  if (!value->IsString()) {
    return std::string();
  }

  return std::string(*(Nan::Utf8String(value)));
}

static Nan::MaybeLocal<v8::Object> BufferOptionValue(v8::Local<v8::Object> options, const char* _key) {
  Nan::HandleScope scope;
  v8::Local<v8::String> key = Nan::New(_key).ToLocalChecked();
  if (options.IsEmpty() || !Nan::Has(options, key).FromMaybe(false)) {
    return Nan::MaybeLocal<v8::Object>();
  }

  v8::Local<v8::Value> value = Nan::Get(options, key).ToLocalChecked();

  if (!node::Buffer::HasInstance(value)) {
    return Nan::MaybeLocal<v8::Object>();
  }

  return Nan::MaybeLocal<v8::Object>(Nan::To<v8::Object>(value));
}

/*
 * Cyrus SASL callback for SASL_CB_GETREALM
 */
static int _zsasl_getrealm(void *context, int id, const char **availrealms,
                           const char **result)
{
  const char *realm = (const char*)context;
  *result = realm;
  return SASL_OK;
}

/*
 * Cyrus SASL callback for SASL_CB_USER or SASL_CB_AUTHNAME
 */
static int _zsasl_simple(void *context, int id, const char **result,
                         unsigned *len)
{
  const char *user = (const char*)context;

  /* paranoia check */
  if (!result)
    return SASL_BADPARAM;

  switch (id) {
  case SASL_CB_USER:
    *result = user;
    break;
  case SASL_CB_AUTHNAME:
    *result = user;
    break;
  default:
    return SASL_BADPARAM;
  }

  return SASL_OK;
}

struct zsasl_secret_ctx {
  // const char *password_file;
  const char *password;
  sasl_secret_t *secret;
};

static int _zsasl_getsecret(sasl_conn_t *conn, void *context, int id,
                            sasl_secret_t **psecret)
{
  struct zsasl_secret_ctx *secret_ctx = (struct zsasl_secret_ctx *)context;
  // TODO: Good enough for PoC, but clean up.
  const char *password = secret_ctx->password;
  size_t len;
  sasl_secret_t *x;

  /* paranoia check */
  if (!conn || !psecret || id != SASL_CB_PASS)
    return SASL_BADPARAM;

  if (!password)
    return SASL_FAIL;

  len = strlen(password);

  x = secret_ctx->secret = (sasl_secret_t *)realloc(
                                                    secret_ctx->secret, sizeof(sasl_secret_t) + len);

  if (!x) {
    memset((void*)password, 0, len);
    return SASL_NOMEM;
  }

  x->len = len;
  strcpy((char *) x->data, password);
  memset((void*)password, 0, len);

  *psecret = x;
  return SASL_OK;
}

typedef int (* sasl_callback_fn_t)(void);

static sasl_callback_t *ExtractCallbacks(v8::Local<v8::Object> options, const char* _key) {
  v8::Local<v8::String> key = Nan::New(_key).ToLocalChecked();
  if (options.IsEmpty() || !Nan::Has(options, key).FromMaybe(false)) {
    return nullptr;
  }

  v8::Local<v8::Object> jcbs = Nan::To<v8::Object>(Nan::Get(options, key).ToLocalChecked()).ToLocalChecked();
  if (jcbs.IsEmpty()) {
    return nullptr;
  }

  std::string realm = StringOptionValue(jcbs, "realm");
  std::string user = StringOptionValue(jcbs, "user");
  std::string password = StringOptionValue(jcbs, "password");

  std::unique_ptr<char[]> z_realm = std::make_unique<char[]>(realm.size() + 1);
  memcpy(z_realm.get(), realm.c_str(), realm.size() + 1);
  sasl_callback_t realm_cb = { SASL_CB_GETREALM, reinterpret_cast<sasl_callback_fn_t>(&_zsasl_getrealm), (void*)z_realm.get() };

  std::unique_ptr<char[]> z_user = std::make_unique<char[]>(user.size() + 1);
  memcpy(z_user.get(), user.c_str(), user.size() + 1);
  sasl_callback_t user_cb = { SASL_CB_USER, reinterpret_cast<sasl_callback_fn_t>(&_zsasl_simple), (void*)z_user.get() };
  sasl_callback_t authname_cb = { SASL_CB_AUTHNAME, reinterpret_cast<sasl_callback_fn_t>(&_zsasl_simple), (void*)z_user.get() };

  std::unique_ptr<char[]> z_password = std::make_unique<char[]>(password.size() + 1);
  memcpy(z_password.get(), password.c_str(), password.size() + 1);
  std::unique_ptr<zsasl_secret_ctx> secret_ctx = std::make_unique<zsasl_secret_ctx>();
  secret_ctx->password = z_password.get();
  sasl_callback_t password_cb = { SASL_CB_PASS, reinterpret_cast<sasl_callback_fn_t>(&_zsasl_getsecret), (void*)secret_ctx.get() };

  std::vector<sasl_callback_t> cbs {
    realm_cb,
    user_cb,
    authname_cb,
    password_cb,
    { SASL_CB_LIST_END, nullptr, nullptr }
  };

  std::unique_ptr<sasl_callback_t[]> c_cbs = std::make_unique<sasl_callback_t[]>(cbs.size());
  std::copy(cbs.begin(), cbs.end(), c_cbs.get());

  z_realm.release();
  z_user.release();
  z_password.release();
  secret_ctx.release();

  return c_cbs.release();
}

NAN_METHOD(SaslWrapper::Connect) {
  SaslWrapper* obj = Nan::ObjectWrap::Unwrap<SaslWrapper>(info.This());
  v8::Local<v8::Object> options = Nan::To<v8::Object>(info[0]).ToLocalChecked();

  std::string service = StringOptionValue(options, "service");
  std::string serverFQDN = StringOptionValue(options, "serverFQDN");
  std::string iplocalport = StringOptionValue(options, "iplocalport");
  std::string ipremoteport = StringOptionValue(options, "ipremoteport");
  sasl_callback_t *prompt_supp = ExtractCallbacks(options, "prompt_supp");

  // TODO: Dispose existing conn.

  int sr = sasl_client_new(service.c_str(),
                           serverFQDN.c_str(),
                           iplocalport != "" ? iplocalport.c_str() : nullptr,
                           ipremoteport != "" ? ipremoteport.c_str() : nullptr,
                           prompt_supp,
                           /*flags*/0,
                           &obj->_conn);

  v8::Local<v8::Object> result = Nan::New<v8::Object>();

  if (sr != SASL_OK) {
    const char *errstring = sasl_errstring(sr, nullptr, nullptr);

    if (!errstring) {
      errstring = "?";
    }

    Nan::Set(result, Nan::New("error").ToLocalChecked(), Nan::New(errstring).ToLocalChecked());
  }

  info.GetReturnValue().Set(result);
}

NAN_METHOD(SaslWrapper::ClientStart) {
  SaslWrapper* obj = Nan::ObjectWrap::Unwrap<SaslWrapper>(info.This());
  v8::Local<v8::Object> options = Nan::To<v8::Object>(info[0]).ToLocalChecked();

  std::string mechlist = StringOptionValue(options, "mechlist");

  const char *mech;
  const char *clientout;
  unsigned clientoutlen;

  int sr = sasl_client_start(obj->_conn,
                             mechlist.c_str(),
                             /*prompt_need*/nullptr,
                             &clientout,
                             &clientoutlen,
                             &mech);

  v8::Local<v8::Object> result = Nan::New<v8::Object>();

  if (sr != SASL_OK && sr != SASL_CONTINUE) {
    const char *errstring = sasl_errstring(sr, nullptr, nullptr);

    if (!errstring) {
      errstring = "?";
    }

    Nan::Set(result, Nan::New("error").ToLocalChecked(), Nan::New(errstring).ToLocalChecked());
  } else {
    char *clientout_own = new char[clientoutlen];

    if (clientoutlen > 0)
      std::copy(clientout, clientout + clientoutlen, clientout_own);

    Nan::Set(result, Nan::New("mech").ToLocalChecked(), Nan::New(mech).ToLocalChecked());
    Nan::Set(result, Nan::New("clientout").ToLocalChecked(), Nan::NewBuffer(clientout_own, clientoutlen).ToLocalChecked());
  }

  info.GetReturnValue().Set(result);
}

NAN_METHOD(SaslWrapper::ClientStep) {
  SaslWrapper* obj = Nan::ObjectWrap::Unwrap<SaslWrapper>(info.This());
  v8::Local<v8::Object> options = Nan::To<v8::Object>(info[0]).ToLocalChecked();

  const char *serverin = nullptr;
  unsigned serverinlen = 0;

  Nan::MaybeLocal<v8::Object> serverin_buffer = BufferOptionValue(options, "serverin");

  if (!serverin_buffer.IsEmpty()) {
    v8::Local<v8::Object> buffer = serverin_buffer.ToLocalChecked();

    size_t len = node::Buffer::Length(buffer);;
    serverinlen = len;

    if (serverinlen != len) {
      serverinlen = 0;
    } else {
      serverin = node::Buffer::Data(buffer);
    }
  }

  const char *clientout;
  unsigned clientoutlen;

  int sr = sasl_client_step(obj->_conn,
                            serverin,
                            serverinlen,
                            /*prompt_need*/nullptr,
                            &clientout,
                            &clientoutlen);

  v8::Local<v8::Object> result = Nan::New<v8::Object>();

  if (sr != SASL_OK && sr != SASL_CONTINUE) {
    const char *errstring = sasl_errstring(sr, nullptr, nullptr);

    if (!errstring) {
      errstring = "?";
    }

    Nan::Set(result, Nan::New("error").ToLocalChecked(), Nan::New(errstring).ToLocalChecked());
  } else {
    char *clientout_own = new char[clientoutlen];

    if (clientoutlen > 0)
      std::copy(clientout, clientout + clientoutlen, clientout_own);

    Nan::Set(result, Nan::New("isComplete").ToLocalChecked(), Nan::New(sr != SASL_CONTINUE));
    Nan::Set(result, Nan::New("clientout").ToLocalChecked(), Nan::NewBuffer(clientout_own, clientoutlen).ToLocalChecked());
  }

  info.GetReturnValue().Set(result);
}

NAN_MODULE_INIT(InitAll) {
  sasl_client_init(nullptr);
  SaslWrapper::Init(target);
}

NODE_MODULE(node_sasl_wrapper, InitAll)
