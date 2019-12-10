// Code generated by protoc-gen-go. DO NOT EDIT.
// source: internal/platform/protobuf/v0/gopherchatter.proto

package gopherchatterv0

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type AuthenticateRequest struct {
	Username             string   `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	Password             string   `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AuthenticateRequest) Reset()         { *m = AuthenticateRequest{} }
func (m *AuthenticateRequest) String() string { return proto.CompactTextString(m) }
func (*AuthenticateRequest) ProtoMessage()    {}
func (*AuthenticateRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c8cda079cad55b5, []int{0}
}

func (m *AuthenticateRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AuthenticateRequest.Unmarshal(m, b)
}
func (m *AuthenticateRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AuthenticateRequest.Marshal(b, m, deterministic)
}
func (m *AuthenticateRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuthenticateRequest.Merge(m, src)
}
func (m *AuthenticateRequest) XXX_Size() int {
	return xxx_messageInfo_AuthenticateRequest.Size(m)
}
func (m *AuthenticateRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AuthenticateRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AuthenticateRequest proto.InternalMessageInfo

func (m *AuthenticateRequest) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *AuthenticateRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

type AuthenticateResponse struct {
	Token                string   `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	ExpiresAt            int64    `protobuf:"varint,2,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AuthenticateResponse) Reset()         { *m = AuthenticateResponse{} }
func (m *AuthenticateResponse) String() string { return proto.CompactTextString(m) }
func (*AuthenticateResponse) ProtoMessage()    {}
func (*AuthenticateResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c8cda079cad55b5, []int{1}
}

func (m *AuthenticateResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AuthenticateResponse.Unmarshal(m, b)
}
func (m *AuthenticateResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AuthenticateResponse.Marshal(b, m, deterministic)
}
func (m *AuthenticateResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuthenticateResponse.Merge(m, src)
}
func (m *AuthenticateResponse) XXX_Size() int {
	return xxx_messageInfo_AuthenticateResponse.Size(m)
}
func (m *AuthenticateResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_AuthenticateResponse.DiscardUnknown(m)
}

var xxx_messageInfo_AuthenticateResponse proto.InternalMessageInfo

func (m *AuthenticateResponse) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func (m *AuthenticateResponse) GetExpiresAt() int64 {
	if m != nil {
		return m.ExpiresAt
	}
	return 0
}

type CreateUserRequest struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Password             string   `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
	PasswordConfirm      string   `protobuf:"bytes,3,opt,name=password_confirm,json=passwordConfirm,proto3" json:"password_confirm,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateUserRequest) Reset()         { *m = CreateUserRequest{} }
func (m *CreateUserRequest) String() string { return proto.CompactTextString(m) }
func (*CreateUserRequest) ProtoMessage()    {}
func (*CreateUserRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c8cda079cad55b5, []int{2}
}

func (m *CreateUserRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateUserRequest.Unmarshal(m, b)
}
func (m *CreateUserRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateUserRequest.Marshal(b, m, deterministic)
}
func (m *CreateUserRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateUserRequest.Merge(m, src)
}
func (m *CreateUserRequest) XXX_Size() int {
	return xxx_messageInfo_CreateUserRequest.Size(m)
}
func (m *CreateUserRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateUserRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CreateUserRequest proto.InternalMessageInfo

func (m *CreateUserRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *CreateUserRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

func (m *CreateUserRequest) GetPasswordConfirm() string {
	if m != nil {
		return m.PasswordConfirm
	}
	return ""
}

type CreateUserResponse struct {
	Id                   string   `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name                 string   `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	PasswordHash         string   `protobuf:"bytes,3,opt,name=password_hash,json=passwordHash,proto3" json:"password_hash,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateUserResponse) Reset()         { *m = CreateUserResponse{} }
func (m *CreateUserResponse) String() string { return proto.CompactTextString(m) }
func (*CreateUserResponse) ProtoMessage()    {}
func (*CreateUserResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c8cda079cad55b5, []int{3}
}

func (m *CreateUserResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateUserResponse.Unmarshal(m, b)
}
func (m *CreateUserResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateUserResponse.Marshal(b, m, deterministic)
}
func (m *CreateUserResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateUserResponse.Merge(m, src)
}
func (m *CreateUserResponse) XXX_Size() int {
	return xxx_messageInfo_CreateUserResponse.Size(m)
}
func (m *CreateUserResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateUserResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CreateUserResponse proto.InternalMessageInfo

func (m *CreateUserResponse) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *CreateUserResponse) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *CreateUserResponse) GetPasswordHash() string {
	if m != nil {
		return m.PasswordHash
	}
	return ""
}

type CreateGroupChatRequest struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateGroupChatRequest) Reset()         { *m = CreateGroupChatRequest{} }
func (m *CreateGroupChatRequest) String() string { return proto.CompactTextString(m) }
func (*CreateGroupChatRequest) ProtoMessage()    {}
func (*CreateGroupChatRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c8cda079cad55b5, []int{4}
}

func (m *CreateGroupChatRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateGroupChatRequest.Unmarshal(m, b)
}
func (m *CreateGroupChatRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateGroupChatRequest.Marshal(b, m, deterministic)
}
func (m *CreateGroupChatRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateGroupChatRequest.Merge(m, src)
}
func (m *CreateGroupChatRequest) XXX_Size() int {
	return xxx_messageInfo_CreateGroupChatRequest.Size(m)
}
func (m *CreateGroupChatRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateGroupChatRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CreateGroupChatRequest proto.InternalMessageInfo

func (m *CreateGroupChatRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type CreateGroupChatResponse struct {
	Id                   string   `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name                 string   `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Admin                string   `protobuf:"bytes,3,opt,name=admin,proto3" json:"admin,omitempty"`
	Members              []string `protobuf:"bytes,4,rep,name=members,proto3" json:"members,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateGroupChatResponse) Reset()         { *m = CreateGroupChatResponse{} }
func (m *CreateGroupChatResponse) String() string { return proto.CompactTextString(m) }
func (*CreateGroupChatResponse) ProtoMessage()    {}
func (*CreateGroupChatResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c8cda079cad55b5, []int{5}
}

func (m *CreateGroupChatResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateGroupChatResponse.Unmarshal(m, b)
}
func (m *CreateGroupChatResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateGroupChatResponse.Marshal(b, m, deterministic)
}
func (m *CreateGroupChatResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateGroupChatResponse.Merge(m, src)
}
func (m *CreateGroupChatResponse) XXX_Size() int {
	return xxx_messageInfo_CreateGroupChatResponse.Size(m)
}
func (m *CreateGroupChatResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateGroupChatResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CreateGroupChatResponse proto.InternalMessageInfo

func (m *CreateGroupChatResponse) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *CreateGroupChatResponse) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *CreateGroupChatResponse) GetAdmin() string {
	if m != nil {
		return m.Admin
	}
	return ""
}

func (m *CreateGroupChatResponse) GetMembers() []string {
	if m != nil {
		return m.Members
	}
	return nil
}

func init() {
	proto.RegisterType((*AuthenticateRequest)(nil), "gopherchatter.v0.AuthenticateRequest")
	proto.RegisterType((*AuthenticateResponse)(nil), "gopherchatter.v0.AuthenticateResponse")
	proto.RegisterType((*CreateUserRequest)(nil), "gopherchatter.v0.CreateUserRequest")
	proto.RegisterType((*CreateUserResponse)(nil), "gopherchatter.v0.CreateUserResponse")
	proto.RegisterType((*CreateGroupChatRequest)(nil), "gopherchatter.v0.CreateGroupChatRequest")
	proto.RegisterType((*CreateGroupChatResponse)(nil), "gopherchatter.v0.CreateGroupChatResponse")
}

func init() {
	proto.RegisterFile("internal/platform/protobuf/v0/gopherchatter.proto", fileDescriptor_8c8cda079cad55b5)
}

var fileDescriptor_8c8cda079cad55b5 = []byte{
	// 396 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x53, 0x61, 0x8b, 0xda, 0x40,
	0x10, 0xc5, 0xa8, 0x6d, 0x1d, 0xb4, 0xea, 0x56, 0xda, 0x10, 0x28, 0x48, 0x6c, 0x8b, 0x42, 0x31,
	0xb6, 0xfd, 0x05, 0x36, 0x1f, 0x2c, 0x94, 0x7e, 0x09, 0x94, 0x83, 0x03, 0x91, 0xd5, 0x4c, 0x2e,
	0xe1, 0xcc, 0x6e, 0x6e, 0x77, 0xe3, 0xdd, 0xbf, 0xba, 0xbf, 0x78, 0x98, 0x6c, 0xbc, 0xa8, 0x77,
	0x7a, 0xf7, 0x2d, 0xf3, 0xe6, 0xed, 0x7b, 0x6f, 0x77, 0x26, 0xf0, 0x23, 0x62, 0x0a, 0x05, 0xa3,
	0x6b, 0x27, 0x59, 0x53, 0x15, 0x70, 0x11, 0x3b, 0x89, 0xe0, 0x8a, 0x2f, 0xd3, 0xc0, 0xd9, 0x4c,
	0x9c, 0x2b, 0x9e, 0x84, 0x28, 0x56, 0x21, 0x55, 0x0a, 0xc5, 0x38, 0xeb, 0x90, 0xce, 0x3e, 0xb8,
	0x99, 0xd8, 0xff, 0xe0, 0xc3, 0x34, 0x55, 0x21, 0x32, 0x15, 0xad, 0xa8, 0x42, 0x0f, 0x6f, 0x52,
	0x94, 0x8a, 0x58, 0xf0, 0x2e, 0x95, 0x5b, 0xf1, 0x18, 0xcd, 0x4a, 0xbf, 0x32, 0x6c, 0x78, 0xbb,
	0x7a, 0xdb, 0x4b, 0xa8, 0x94, 0xb7, 0x5c, 0xf8, 0xa6, 0x91, 0xf7, 0x8a, 0xda, 0xfe, 0x0b, 0xbd,
	0x7d, 0x39, 0x99, 0x70, 0x26, 0x91, 0xf4, 0xa0, 0xae, 0xf8, 0x35, 0x32, 0x2d, 0x96, 0x17, 0xe4,
	0x33, 0x00, 0xde, 0x25, 0x91, 0x40, 0xb9, 0xa0, 0x2a, 0xd3, 0xaa, 0x7a, 0x0d, 0x8d, 0x4c, 0x95,
	0xcd, 0xa0, 0xeb, 0x0a, 0xa4, 0x0a, 0xff, 0x4b, 0x14, 0x45, 0x32, 0x02, 0xb5, 0x52, 0xaa, 0xda,
	0xb9, 0x44, 0x64, 0x04, 0x9d, 0xe2, 0x7b, 0xb1, 0xe2, 0x2c, 0x88, 0x44, 0x6c, 0x56, 0x33, 0x4e,
	0xbb, 0xc0, 0xdd, 0x1c, 0xb6, 0xe7, 0x40, 0xca, 0x7e, 0x3a, 0xfa, 0x7b, 0x30, 0x22, 0x5f, 0xdb,
	0x19, 0x91, 0xbf, 0x0b, 0x60, 0x94, 0x02, 0x0c, 0xa0, 0xb5, 0x33, 0x09, 0xa9, 0x0c, 0xb5, 0x43,
	0xb3, 0x00, 0xff, 0x50, 0x19, 0xda, 0xdf, 0xe1, 0x63, 0x2e, 0x3f, 0x13, 0x3c, 0x4d, 0xdc, 0x90,
	0xaa, 0x13, 0x77, 0xb2, 0x63, 0xf8, 0x74, 0xc4, 0x7e, 0x45, 0xa2, 0x1e, 0xd4, 0xa9, 0x1f, 0x47,
	0x4c, 0x27, 0xc9, 0x0b, 0x62, 0xc2, 0xdb, 0x18, 0xe3, 0x25, 0x0a, 0x69, 0xd6, 0xfa, 0xd5, 0x61,
	0xc3, 0x2b, 0xca, 0x9f, 0xf7, 0x06, 0xb4, 0x66, 0xd9, 0x72, 0xb8, 0xf9, 0x72, 0x90, 0x39, 0x34,
	0xcb, 0xa3, 0x24, 0x5f, 0xc7, 0x87, 0xcb, 0x33, 0x7e, 0x62, 0x73, 0xac, 0x6f, 0xe7, 0x68, 0xfa,
	0x12, 0x17, 0x00, 0x8f, 0x8f, 0x4d, 0x06, 0xc7, 0xa7, 0x8e, 0x46, 0x6f, 0x7d, 0x39, 0x4d, 0xd2,
	0xc2, 0x01, 0xb4, 0x0f, 0x1e, 0x8e, 0x0c, 0x9f, 0x3b, 0x78, 0x38, 0x09, 0x6b, 0xf4, 0x02, 0x66,
	0xee, 0xf3, 0xbb, 0x7b, 0xd9, 0xde, 0xe3, 0x6e, 0x26, 0xcb, 0x37, 0xd9, 0x5f, 0xf6, 0xeb, 0x21,
	0x00, 0x00, 0xff, 0xff, 0x19, 0x33, 0x57, 0xcf, 0x9a, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// GopherChatterClient is the client API for GopherChatter service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type GopherChatterClient interface {
	Authenticate(ctx context.Context, in *AuthenticateRequest, opts ...grpc.CallOption) (*AuthenticateResponse, error)
	CreateUser(ctx context.Context, in *CreateUserRequest, opts ...grpc.CallOption) (*CreateUserResponse, error)
	CreateGroupChat(ctx context.Context, in *CreateGroupChatRequest, opts ...grpc.CallOption) (*CreateGroupChatResponse, error)
}

type gopherChatterClient struct {
	cc *grpc.ClientConn
}

func NewGopherChatterClient(cc *grpc.ClientConn) GopherChatterClient {
	return &gopherChatterClient{cc}
}

func (c *gopherChatterClient) Authenticate(ctx context.Context, in *AuthenticateRequest, opts ...grpc.CallOption) (*AuthenticateResponse, error) {
	out := new(AuthenticateResponse)
	err := c.cc.Invoke(ctx, "/gopherchatter.v0.GopherChatter/Authenticate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gopherChatterClient) CreateUser(ctx context.Context, in *CreateUserRequest, opts ...grpc.CallOption) (*CreateUserResponse, error) {
	out := new(CreateUserResponse)
	err := c.cc.Invoke(ctx, "/gopherchatter.v0.GopherChatter/CreateUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gopherChatterClient) CreateGroupChat(ctx context.Context, in *CreateGroupChatRequest, opts ...grpc.CallOption) (*CreateGroupChatResponse, error) {
	out := new(CreateGroupChatResponse)
	err := c.cc.Invoke(ctx, "/gopherchatter.v0.GopherChatter/CreateGroupChat", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GopherChatterServer is the server API for GopherChatter service.
type GopherChatterServer interface {
	Authenticate(context.Context, *AuthenticateRequest) (*AuthenticateResponse, error)
	CreateUser(context.Context, *CreateUserRequest) (*CreateUserResponse, error)
	CreateGroupChat(context.Context, *CreateGroupChatRequest) (*CreateGroupChatResponse, error)
}

// UnimplementedGopherChatterServer can be embedded to have forward compatible implementations.
type UnimplementedGopherChatterServer struct {
}

func (*UnimplementedGopherChatterServer) Authenticate(ctx context.Context, req *AuthenticateRequest) (*AuthenticateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Authenticate not implemented")
}
func (*UnimplementedGopherChatterServer) CreateUser(ctx context.Context, req *CreateUserRequest) (*CreateUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateUser not implemented")
}
func (*UnimplementedGopherChatterServer) CreateGroupChat(ctx context.Context, req *CreateGroupChatRequest) (*CreateGroupChatResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateGroupChat not implemented")
}

func RegisterGopherChatterServer(s *grpc.Server, srv GopherChatterServer) {
	s.RegisterService(&_GopherChatter_serviceDesc, srv)
}

func _GopherChatter_Authenticate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthenticateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GopherChatterServer).Authenticate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gopherchatter.v0.GopherChatter/Authenticate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GopherChatterServer).Authenticate(ctx, req.(*AuthenticateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GopherChatter_CreateUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GopherChatterServer).CreateUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gopherchatter.v0.GopherChatter/CreateUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GopherChatterServer).CreateUser(ctx, req.(*CreateUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GopherChatter_CreateGroupChat_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateGroupChatRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GopherChatterServer).CreateGroupChat(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gopherchatter.v0.GopherChatter/CreateGroupChat",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GopherChatterServer).CreateGroupChat(ctx, req.(*CreateGroupChatRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _GopherChatter_serviceDesc = grpc.ServiceDesc{
	ServiceName: "gopherchatter.v0.GopherChatter",
	HandlerType: (*GopherChatterServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Authenticate",
			Handler:    _GopherChatter_Authenticate_Handler,
		},
		{
			MethodName: "CreateUser",
			Handler:    _GopherChatter_CreateUser_Handler,
		},
		{
			MethodName: "CreateGroupChat",
			Handler:    _GopherChatter_CreateGroupChat_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "internal/platform/protobuf/v0/gopherchatter.proto",
}
