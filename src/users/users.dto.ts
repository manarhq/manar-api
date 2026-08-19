import { ApiProperty } from '@nestjs/swagger';
import { ROLES } from '../auth/roles';

/** One `RoleBinding` row, as returned by every `/users` surface. */
export class RoleBindingDto {
  @ApiProperty({ enum: ROLES })
  role!: string;

  @ApiProperty({ format: 'date-time' })
  grantedAt!: Date;

  @ApiProperty({
    description:
      'Free-text identifier of who/what granted this role — a UserProfile id for a Manar-side grant (Phase 14), or "keycloak:realm_access" for a role JwtAuthGuard synced directly from the token (see docs/human-auth.md).',
  })
  grantedBy!: string;
}

/** `UserProfile` plus its current `RoleBinding`s — the shape every `/users` endpoint returns. */
export class UserSummaryDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({
    description:
      'The Keycloak JWT `sub` claim this user was found-or-created from.',
  })
  keycloakSubject!: string;

  @ApiProperty()
  email!: string;

  @ApiProperty()
  displayName!: string;

  @ApiProperty({ format: 'date-time' })
  createdAt!: Date;

  @ApiProperty({ format: 'date-time' })
  lastSeenAt!: Date;

  @ApiProperty({ type: () => RoleBindingDto, isArray: true })
  roles!: RoleBindingDto[];
}

/** `GET /users`'s response envelope — see `AgentListResponseDto`'s identical shape/doc comment. */
export class UserListResponseDto {
  @ApiProperty({ type: () => UserSummaryDto, isArray: true })
  items!: UserSummaryDto[];

  @ApiProperty({ nullable: true })
  nextCursor!: string | null;
}

/** Mirrors `GrantRoleRequestSchema`. */
export class GrantRoleRequestDto {
  @ApiProperty({ enum: ROLES })
  role!: string;
}
