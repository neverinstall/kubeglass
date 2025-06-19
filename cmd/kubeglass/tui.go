package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cilium/ebpf/ringbuf"
)

type keyMap struct {
	Quit         key.Binding
	Filter       key.Binding
	Clear        key.Binding
	ToggleAll    key.Binding
	ToggleBinary key.Binding
	ToggleHelp   key.Binding
}

var keys = keyMap{
	Quit:         key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	Filter:       key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
	Clear:        key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "clear filter")),
	ToggleAll:    key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "toggle all fds")),
	ToggleBinary: key.NewBinding(key.WithKeys("b"), key.WithHelp("b", "toggle binary")),
	ToggleHelp:   key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "toggle help")),
}

type tuiModel struct {
	ctx   context.Context
	rd    *ringbuf.Reader
	keys  keyMap
	help  help.Model
	input textinput.Model

	showAll    bool
	fdFilter   map[uint32]bool
	skipBinary bool
	grepRegex  *regexp.Regexp
	filtering  bool
	err        error

	events   []string
	viewport viewport.Model
	ready    bool
}

func newTUIModel(ctx context.Context, rd *ringbuf.Reader) *tuiModel {
	ti := textinput.New()
	ti.Placeholder = "Filter regex..."
	ti.Focus()

	return &tuiModel{
		ctx:        ctx,
		rd:         rd,
		keys:       keys,
		help:       help.New(),
		input:      ti,
		showAll:    true,
		fdFilter:   make(map[uint32]bool),
		skipBinary: true,
		filtering:  false,
	}
}

func (m *tuiModel) pollNextEvent() tea.Msg {
	for {
		record, err := m.rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed || err == io.EOF {
				return nil
			}
			return err
		}

		var bpfEvent bpfWriteEvent
		if err := binary.Read(strings.NewReader(string(record.RawSample)), binary.LittleEndian, &bpfEvent); err != nil {
			return err
		}

		event := Event{
			PID:     bpfEvent.PID,
			FD:      bpfEvent.FD,
			Payload: bpfEvent.Data[:bpfEvent.DataLen],
		}

		if !m.showAll && !m.fdFilter[event.FD] {
			continue
		}
		if m.skipBinary && !isPrintable(event.Payload) {
			continue
		}
		if m.grepRegex != nil && !m.grepRegex.Match(event.Payload) {
			continue
		}

		return event
	}
}

func (m *tuiModel) Init() tea.Cmd {
	return m.pollNextEvent
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.help.Width = msg.Width
		headerHeight := lipgloss.Height(m.headerView())
		footerHeight := lipgloss.Height(m.footerView())
		verticalMarginHeight := headerHeight + footerHeight

		if !m.ready {
			m.viewport = viewport.New(msg.Width, msg.Height-verticalMarginHeight)
			m.viewport.YPosition = headerHeight
			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = msg.Height - verticalMarginHeight
		}

	case Event:
		line := fmt.Sprintf("[PID %d, %s] %s", msg.PID, fdString(msg.FD), formatData(msg.Payload))
		m.events = append(m.events, line)
		m.viewport.SetContent(strings.Join(m.events, "\n"))
		m.viewport.GotoBottom()
		return m, m.pollNextEvent

	case error:
		m.err = msg
		return m, tea.Quit

	case tea.KeyMsg:
		if m.filtering {
			switch {
			case key.Matches(msg, keys.Quit):
				m.filtering = false
				m.input.Blur()
			case key.Matches(msg, key.NewBinding(key.WithKeys("enter"))):
				m.grepRegex, _ = regexp.Compile(m.input.Value())
				m.filtering = false
				m.input.Blur()
			default:
				m.input, cmd = m.input.Update(msg)
				cmds = append(cmds, cmd)
			}
		} else {
			switch {
			case key.Matches(msg, m.keys.Quit):
				return m, tea.Quit
			case key.Matches(msg, m.keys.Filter):
				m.filtering = true
				m.input.Focus()
				return m, nil
			case key.Matches(msg, m.keys.Clear):
				m.input.Reset()
				m.grepRegex = nil
			case key.Matches(msg, m.keys.ToggleAll):
				m.showAll = !m.showAll
			case key.Matches(msg, m.keys.ToggleBinary):
				m.skipBinary = !m.skipBinary
			case key.Matches(msg, m.keys.ToggleHelp):
				m.help.ShowAll = !m.help.ShowAll
			}
		}
	}

	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m *tuiModel) View() string {
	if !m.ready {
		return "\n  Initializing..."
	}
	return fmt.Sprintf("%s\n%s\n%s", m.headerView(), m.viewport.View(), m.footerView())
}

func (m *tuiModel) headerView() string {
	title := titleStyle.Render("kubeglass")
	line := strings.Repeat("─", m.viewport.Width)
	return lipgloss.JoinVertical(lipgloss.Left, title, line)
}

func (m *tuiModel) footerView() string {
	var status string
	if m.filtering {
		status = "FILTERING"
	} else if m.grepRegex != nil {
		status = "FILTER: " + m.grepRegex.String()
	} else {
		status = "ALL"
	}

	info := infoStyle.Render(fmt.Sprintf("%3.f%%", m.viewport.ScrollPercent()*100))

	spacer := ""
	if m.ready {
		if w := m.viewport.Width - lipgloss.Width(status) - lipgloss.Width(info); w > 0 {
			spacer = strings.Repeat(" ", w)
		}
	}

	statusBar := lipgloss.JoinHorizontal(lipgloss.Bottom, status, spacer, info)

	helpView := m.help.View(m.keys)
	return lipgloss.JoinVertical(lipgloss.Bottom, helpView, statusBar)
}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			PaddingLeft(2).
			PaddingRight(2)

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#DDDADA")).
			Align(lipgloss.Right)
)

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Quit, k.Filter, k.ToggleHelp}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Quit, k.Filter, k.Clear},
		{k.ToggleAll, k.ToggleBinary, k.ToggleHelp},
	}
}
