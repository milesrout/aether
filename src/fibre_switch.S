/* This file is part of Æther.
 *
 * Æther is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Æther is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

.globl fibre_switch
fibre_switch:
	mov	%rsp, 0x00(%rdi)
	mov	%r15, 0x08(%rdi)
	mov	%r14, 0x10(%rdi)
	mov	%r13, 0x18(%rdi)
	mov	%r12, 0x20(%rdi)
	mov	%rbx, 0x28(%rdi)
	mov	%rbp, 0x30(%rdi)

	mov	0x00(%rsi), %rsp
	mov	0x08(%rsi), %r15
	mov	0x10(%rsi), %r14
	mov	0x18(%rsi), %r13
	mov	0x20(%rsi), %r12
	mov	0x28(%rsi), %rbx
	mov	0x30(%rsi), %rbp

	ret
