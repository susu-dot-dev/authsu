package orgs

import (
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// MemberListResponse is the body of GET /api/org/{id}/member: one page, newest
// first.
type MemberListResponse struct {
	Members []Member `json:"members"`

	// Next is the cursor of the following page, to send as the cursor query
	// parameter. It is absent on the last page.
	Next string `json:"next,omitempty"`
}

// listMembers answers GET /api/org/{id}/member. The organization not being one
// the caller may see is a 404 about the organization, as for GET /api/org/{id}.
func (d Deps) listMembers(call *auth.Call) result.Result[httpapi.Response] {
	return parsePage(call.Request.Query).
		Then(func(p page) (store.MemberPage, error) {
			return d.Store.ListMembers(
				call.Request.Context, call.ID(), call.Principal.UserID, auth.RoleAdmin, p.cursor, p.limit)
		}).
		MapErr(asOrg).
		Map(func(stored store.MemberPage) MemberListResponse {
			out := MemberListResponse{Members: make([]Member, 0, len(stored.Members)), Next: stored.Next}

			for _, member := range stored.Members {
				out.Members = append(out.Members, presentMember(member))
			}

			return out
		}).
		Map(ok)
}

// setAdminBody is the body of PATCH /api/member/{id}.
type setAdminBody struct {
	// Admin is whether the member is to administer their organization. It is
	// required (input.ParseOrgAdmin): a pointer, so that leaving it out is not
	// read as false.
	Admin *bool `json:"admin"`
}

// setMemberAdmin answers PATCH /api/member/{id}: {id} is the user's id.
func (d Deps) setMemberAdmin(call *auth.Call) result.Result[httpapi.Response] {
	return httpapi.Decode[setAdminBody](call.Request).
		Then(func(body setAdminBody) (input.OrgAdmin, error) { return input.ParseOrgAdmin(body.Admin) }).
		Then(func(admin input.OrgAdmin) (store.Member, error) {
			return d.Store.SetMemberAdmin(
				call.Request.Context, call.ID(), admin.Admin(), call.Principal.UserID, auth.RoleAdmin, d.Now())
		}).
		MapErr(asMember).
		Map(func(stored store.Member) httpapi.Response { return ok(presentMember(stored)) })
}

// revokeMember answers DELETE /api/member/{id}: {id} is the user's id. It revokes
// the member's account, and the response is the member as revoked. The caller
// is a platform administrator, or administers the member's organization and
// does not revoke a platform administrator or themself: the store decides.
func (d Deps) revokeMember(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(d.Store.RevokeMember(
		call.Request.Context, call.ID(), call.Principal.UserID, auth.RoleAdmin, d.Now())).
		MapErr(asMember).
		Map(func(stored store.Member) httpapi.Response { return ok(presentMember(stored)) })
}
