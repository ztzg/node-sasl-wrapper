#ifndef NODE_SASL_WRAPPER_H
#define NODE_SASL_WRAPPER_H

#include <nan.h>

#include <sasl/sasl.h>

class SaslWrapper : public Nan::ObjectWrap {
public:
  static NAN_MODULE_INIT(Init);

private:
  explicit SaslWrapper();
  ~SaslWrapper();

  static NAN_METHOD(New);
  static NAN_METHOD(Connect);
  static NAN_METHOD(ClientStart);
  static NAN_METHOD(ClientStep);
  static Nan::Persistent<v8::Function> constructor;
  sasl_conn_t* _conn;
};

#endif /* NODE_SASL_WRAPPER_H */
