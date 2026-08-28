import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { PageLoading } from './PageLoading'
import { PageError } from './PageError'
import { PageEmpty } from './PageEmpty'

describe('PageStates Components', () => {
  describe('PageLoading', () => {
    it('renders table skeleton by default without loading text', () => {
      render(<PageLoading />)
      expect(screen.getByTestId('page-loading-table')).toBeInTheDocument()
      expect(screen.queryByText(/loading/i)).not.toBeInTheDocument()
    })

    it('renders card skeleton variant', () => {
      render(<PageLoading variant="card" />)
      expect(screen.getByTestId('page-loading-card')).toBeInTheDocument()
      expect(screen.queryByText(/loading/i)).not.toBeInTheDocument()
    })

    it('renders detail skeleton variant', () => {
      render(<PageLoading variant="detail" />)
      expect(screen.getByTestId('page-loading-detail')).toBeInTheDocument()
      expect(screen.queryByText(/loading/i)).not.toBeInTheDocument()
    })
  })

  describe('PageError', () => {
    it('renders error message and retry button when onRetry provided', () => {
      const onRetry = vi.fn()
      render(<PageError error={new Error('Failed to fetch data')} onRetry={onRetry} />)

      expect(screen.getByText('Failed to fetch data')).toBeInTheDocument()
      const retryBtn = screen.getByRole('button', { name: /retry/i })
      expect(retryBtn).toBeInTheDocument()

      fireEvent.click(retryBtn)
      expect(onRetry).toHaveBeenCalledTimes(1)
    })

    it('handles string error without retry button when onRetry is omitted', () => {
      render(<PageError error="Network error occurred" />)
      expect(screen.getByText('Network error occurred')).toBeInTheDocument()
      expect(screen.queryByRole('button')).not.toBeInTheDocument()
    })

    it('truncates error messages longer than 200 characters', () => {
      const longMessage = 'A'.repeat(300)
      render(<PageError error={longMessage} />)
      expect(screen.getByText('A'.repeat(200))).toBeInTheDocument()
    })
  })

  describe('PageEmpty', () => {
    it('renders title and description', () => {
      render(
        <PageEmpty
          title="No results found"
          description="Try adjusting your search criteria"
        />
      )

      expect(screen.getByText('No results found')).toBeInTheDocument()
      expect(screen.getByText('Try adjusting your search criteria')).toBeInTheDocument()
      expect(screen.queryByRole('button')).not.toBeInTheDocument()
    })

    it('renders action button when action prop is provided and triggers callback', () => {
      const onClick = vi.fn()
      render(
        <PageEmpty
          title="No projects yet"
          description="Get started by creating your first project"
          action={{
            label: 'Create Project',
            onClick,
          }}
        />
      )

      const actionBtn = screen.getByRole('button', { name: 'Create Project' })
      expect(actionBtn).toBeInTheDocument()

      fireEvent.click(actionBtn)
      expect(onClick).toHaveBeenCalledTimes(1)
    })
  })
})
